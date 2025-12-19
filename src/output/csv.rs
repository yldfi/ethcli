//! CSV output writer

use crate::abi::{DecodedLog, DecodedValue};
use crate::error::{OutputError, Result};
use crate::fetcher::FetchResult;
use crate::output::OutputWriter;
use alloy::rpc::types::Log;
use std::fs::File;
use std::io::{self, BufWriter, Write};
use std::path::Path;

/// CSV output writer
pub struct CsvWriter {
    /// CSV writer
    writer: csv::Writer<Box<dyn Write + Send>>,
    /// Known column names (sorted for consistent output)
    columns: Vec<String>,
    /// Whether header has been written
    header_written: bool,
    /// Buffered rows (before header is determined)
    buffer: Vec<DecodedLog>,
    /// Max rows to buffer before writing header
    max_buffer: usize,
}

impl CsvWriter {
    /// Create a new CSV writer
    pub fn new(path: Option<&Path>) -> Result<Self> {
        let output: Box<dyn Write + Send> = if let Some(p) = path {
            let file = File::create(p)
                .map_err(|e| OutputError::FileCreate(format!("{}: {}", p.display(), e)))?;
            Box::new(BufWriter::new(file))
        } else {
            Box::new(BufWriter::new(io::stdout()))
        };

        let writer = csv::Writer::from_writer(output);

        Ok(Self {
            writer,
            columns: Vec::new(),
            header_written: false,
            buffer: Vec::new(),
            max_buffer: 100, // Buffer up to 100 rows to determine columns
        })
    }

    /// Collect all unique column names from a log
    fn collect_columns(&mut self, log: &DecodedLog) {
        for key in log.params.keys() {
            if !self.columns.contains(key) {
                self.columns.push(key.clone());
            }
        }
    }

    /// Write header row
    fn write_header(&mut self) -> Result<()> {
        // Sort columns for consistent output
        self.columns.sort();

        // Build header
        let mut header = vec![
            "block_number".to_string(),
            "transaction_hash".to_string(),
            "log_index".to_string(),
            "address".to_string(),
            "event_name".to_string(),
        ];
        header.extend(self.columns.clone());

        self.writer
            .write_record(&header)
            .map_err(|e| OutputError::CsvWrite(e.to_string()))?;

        self.header_written = true;
        Ok(())
    }

    /// Write a single decoded log as a row
    fn write_row(&mut self, log: &DecodedLog) -> Result<()> {
        let mut row = vec![
            log.block_number.to_string(),
            format!("{:#x}", log.transaction_hash),
            log.log_index.to_string(),
            format!("{:#x}", log.address),
            log.event_name.clone(),
        ];

        // Add parameter values in column order
        for col in &self.columns {
            let value = log
                .params
                .get(col)
                .map(|v| Self::value_to_string(v))
                .unwrap_or_default();
            row.push(value);
        }

        self.writer
            .write_record(&row)
            .map_err(|e| OutputError::CsvWrite(e.to_string()))?;

        Ok(())
    }

    /// Convert a decoded value to string
    fn value_to_string(value: &DecodedValue) -> String {
        match value {
            DecodedValue::Address(s) => s.clone(),
            DecodedValue::Uint(s) => s.clone(),
            DecodedValue::Int(s) => s.clone(),
            DecodedValue::Bool(b) => b.to_string(),
            DecodedValue::Bytes(s) => s.clone(),
            DecodedValue::String(s) => s.clone(),
            DecodedValue::Array(arr) => {
                let items: Vec<String> = arr.iter().map(Self::value_to_string).collect();
                format!("[{}]", items.join(","))
            }
            DecodedValue::Tuple(arr) => {
                let items: Vec<String> = arr.iter().map(Self::value_to_string).collect();
                format!("({})", items.join(","))
            }
        }
    }

    /// Flush buffer and write header
    fn flush_buffer(&mut self) -> Result<()> {
        if self.buffer.is_empty() {
            return Ok(());
        }

        // Collect columns from all buffered rows
        for log in &self.buffer {
            let mut new_cols: Vec<String> = log
                .params
                .keys()
                .filter(|k| !self.columns.contains(*k))
                .cloned()
                .collect();
            self.columns.append(&mut new_cols);
        }

        // Write header
        self.write_header()?;

        // Write buffered rows
        let buffer = std::mem::take(&mut self.buffer);
        for log in buffer {
            self.write_row(&log)?;
        }

        Ok(())
    }

    /// Write raw log (limited CSV support)
    fn write_raw_log(&mut self, log: &Log) -> Result<()> {
        if !self.header_written {
            self.writer
                .write_record(&[
                    "block_number",
                    "transaction_hash",
                    "log_index",
                    "address",
                    "topics",
                    "data",
                ])
                .map_err(|e| OutputError::CsvWrite(e.to_string()))?;
            self.header_written = true;
        }

        let topics: Vec<String> = log.topics().iter().map(|t| format!("{:#x}", t)).collect();

        self.writer
            .write_record(&[
                log.block_number.unwrap_or(0).to_string(),
                format!("{:#x}", log.transaction_hash.unwrap_or_default()),
                log.log_index.unwrap_or(0).to_string(),
                format!("{:#x}", log.address()),
                topics.join(";"),
                format!("0x{}", hex::encode(&log.data().data)),
            ])
            .map_err(|e| OutputError::CsvWrite(e.to_string()))?;

        Ok(())
    }
}

impl OutputWriter for CsvWriter {
    fn write_logs(&mut self, result: &FetchResult) -> Result<()> {
        match result {
            FetchResult::Decoded(logs) => {
                for log in logs {
                    if !self.header_written {
                        // Buffer rows until we have enough to determine columns
                        self.collect_columns(log);
                        self.buffer.push(log.clone());

                        if self.buffer.len() >= self.max_buffer {
                            self.flush_buffer()?;
                        }
                    } else {
                        // Check for new columns
                        let new_cols: Vec<String> = log
                            .params
                            .keys()
                            .filter(|k| !self.columns.contains(*k))
                            .cloned()
                            .collect();

                        if !new_cols.is_empty() {
                            tracing::warn!(
                                "New columns found after header written: {:?}",
                                new_cols
                            );
                        }

                        self.write_row(log)?;
                    }
                }
            }
            FetchResult::Raw(logs) => {
                for log in logs {
                    self.write_raw_log(log)?;
                }
            }
        }
        Ok(())
    }

    fn finalize(&mut self) -> Result<()> {
        // Flush any remaining buffer
        if !self.header_written && !self.buffer.is_empty() {
            self.flush_buffer()?;
        }

        self.writer
            .flush()
            .map_err(|e| OutputError::CsvWrite(e.to_string()))?;

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_value_to_string() {
        assert_eq!(
            CsvWriter::value_to_string(&DecodedValue::Uint("1000".to_string())),
            "1000"
        );

        assert_eq!(
            CsvWriter::value_to_string(&DecodedValue::Bool(true)),
            "true"
        );

        assert_eq!(
            CsvWriter::value_to_string(&DecodedValue::Array(vec![
                DecodedValue::Uint("1".to_string()),
                DecodedValue::Uint("2".to_string()),
            ])),
            "[1,2]"
        );
    }
}
