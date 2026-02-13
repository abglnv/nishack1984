use anyhow::Result;
use base64::{engine::general_purpose, Engine as _};
use screenshots::Screen;
use std::io::Cursor;
use tracing::{info, warn};

/// Captures a screenshot of the primary display and returns it as a base64-encoded JPEG.
pub fn capture_screenshot(quality: u8, max_dimension: u32) -> Result<String> {
    // Retry screen enumeration — after sleep/wake the GPU driver may need
    // a moment before displays are available again.
    let mut last_err = anyhow::anyhow!("No screens found");
    let mut screen_capture = None;

    for attempt in 0..3 {
        match Screen::all() {
            Ok(screens) => {
                if let Some(s) = screens.first() {
                    match s.capture() {
                        Ok(img) => {
                            screen_capture = Some((img, s.display_info));
                            break;
                        }
                        Err(e) => last_err = e.into(),
                    }
                }
            }
            Err(e) => last_err = e.into(),
        }
        if attempt < 2 {
            std::thread::sleep(std::time::Duration::from_millis(500));
        }
    }

    let (image, display_info) = screen_capture
        .ok_or(last_err)?;

    info!("Capturing screenshot from display: {:?}", display_info);

    // Convert to image crate format
    let width = image.width();
    let height = image.height();
    let rgba_data = image.rgba();
    
    let img = image::DynamicImage::ImageRgba8(
        image::RgbaImage::from_raw(
            width,
            height,
            rgba_data.to_vec(),
        )
        .ok_or_else(|| anyhow::anyhow!("Failed to create image from screenshot"))?
    );

    // Resize if needed
    let img = if img.width() > max_dimension || img.height() > max_dimension {
        let ratio = (max_dimension as f32) / img.width().max(img.height()) as f32;
        let new_width = (img.width() as f32 * ratio) as u32;
        let new_height = (img.height() as f32 * ratio) as u32;
        info!("Resizing screenshot from {}x{} to {}x{}", 
              img.width(), img.height(), new_width, new_height);
        img.resize(new_width, new_height, image::imageops::FilterType::Lanczos3)
    } else {
        img
    };

    // Encode as JPEG with quality
    let mut buffer = Cursor::new(Vec::new());
    let encoder = image::codecs::jpeg::JpegEncoder::new_with_quality(&mut buffer, quality);
    img.write_with_encoder(encoder)?;

    // Encode to base64
    let base64_img = general_purpose::STANDARD.encode(buffer.into_inner());
    
    info!("Screenshot captured: {} bytes (base64)", base64_img.len());
    
    Ok(base64_img)
}

/// Captures a screenshot and handles errors gracefully.
pub fn try_capture_screenshot(quality: u8, max_dimension: u32) -> Option<String> {
    match capture_screenshot(quality, max_dimension) {
        Ok(data) => Some(data),
        Err(e) => {
            warn!("Failed to capture screenshot: {}", e);
            None
        }
    }
}
