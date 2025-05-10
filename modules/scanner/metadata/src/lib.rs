
use std::path::Path;
use serde::{Serialize, Deserialize};
use chrono::{DateTime, Utc};
use exif::{Reader, In, Tag};
use lopdf::Document;
use office::prelude::*;
use anyhow::{Result, Context};

#[derive(Debug, Serialize, Deserialize)]
pub struct Metadata {
    pub filename: String,
    pub file_type: String,
    pub size_bytes: u64,
    pub created_at: Option<DateTime<Utc>>,
    pub modified_at: Option<DateTime<Utc>>,
    pub author: Option<String>,
    pub location: Option<Location>,
    pub software: Option<String>,
    pub sanitized_fields: Vec<String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct Location {
    pub latitude: f64,
    pub longitude: f64,
}

pub struct MetadataExtractor;

impl MetadataExtractor {
    pub fn new() -> Self {
        Self {}
    }
    
    pub fn extract_all<P: AsRef<Path>>(&self, path: P) -> Result<Metadata> {
        let path = path.as_ref();
        let extension = path.extension()
            .and_then(|e| e.to_str())
            .unwrap_or("")
            .to_lowercase();
            
        let metadata = match extension.as_str() {
            "pdf" => self.extract_pdf(path),
            "jpg" | "jpeg" => self.extract_jpeg(path),
            "docx" => self.extract_docx(path),
            _ => Err(anyhow::anyhow!("Unsupported file type"))
        }?;
        
        Ok(metadata)
    }
    
    fn extract_pdf(&self, path: &Path) -> Result<Metadata> {
        let doc = Document::load(path)
            .context("Failed to load PDF")?;
            
        let info = doc.get_info()
            .context("Failed to get PDF info")?;
            
        Ok(Metadata {
            filename: path.file_name()
                .and_then(|n| n.to_str())
                .unwrap_or("")
                .to_string(),
            file_type: "pdf".to_string(),
            size_bytes: std::fs::metadata(path)?.len(),
            created_at: None, // Parse from PDF metadata
            modified_at: None,
            author: info.get("Author")
                .and_then(|a| a.as_string())
                .map(|s| s.to_string()),
            location: None,
            software: info.get("Producer")
                .and_then(|p| p.as_string())
                .map(|s| s.to_string()),
            sanitized_fields: vec![],
        })
    }
    
    fn extract_jpeg(&self, path: &Path) -> Result<Metadata> {
        let file = std::fs::File::open(path)?;
        let reader = Reader::new()
            .read_from_container(&mut std::io::BufReader::new(file))?;
            
        let mut metadata = Metadata {
            filename: path.file_name()
                .and_then(|n| n.to_str())
                .unwrap_or("")
                .to_string(),
            file_type: "jpeg".to_string(),
            size_bytes: std::fs::metadata(path)?.len(),
            created_at: None,
            modified_at: None,
            author: None,
            location: None,
            software: None,
            sanitized_fields: vec![],
        };
        
        // Extract GPS coordinates if available
        if let Some(lat) = reader.get_field(Tag::GPSLatitude) {
            if let Some(lon) = reader.get_field(Tag::GPSLongitude) {
                metadata.location = Some(Location {
                    latitude: lat.value.get_rational(0).map(|r| r.to_f64()).unwrap_or(0.0),
                    longitude: lon.value.get_rational(0).map(|r| r.to_f64()).unwrap_or(0.0),
                });
                metadata.sanitized_fields.push("gps_coordinates".to_string());
            }
        }
        
        Ok(metadata)
    }
}
