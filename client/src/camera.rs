// Camera capture via `nokhwa` (DirectShow/MediaFoundation backend on Windows).
// Streams JPEG frames to the server.

use std::{
    sync::{atomic::{AtomicBool, Ordering}, Arc},
    thread,
    time::{Duration, Instant},
};
use base64::{engine::general_purpose::STANDARD, Engine};
use nokhwa::{
    pixel_format::RgbFormat,
    utils::{CameraIndex, RequestedFormat, RequestedFormatType},
    Camera,
};
use image::ImageBuffer;
use image::codecs::jpeg::JpegEncoder;

use crate::Sock;
use crate::send;

pub fn stream_loop(sock: Sock, flag: Arc<AtomicBool>, fps: u32) {
    let interval = Duration::from_millis(1000 / fps.max(1) as u64);

    // Open camera once and keep it open for the duration
    let fmt = RequestedFormat::new::<RgbFormat>(RequestedFormatType::AbsoluteHighestResolution);
    let mut cam = match Camera::new(CameraIndex::Index(0), fmt) {
        Ok(c) => c,
        Err(_) => return, // camera unavailable — silently exit
    };

    if cam.open_stream().is_err() { return; }

    while flag.load(Ordering::SeqCst) {
        let t0 = Instant::now();

        if let Ok(frame) = cam.frame() {
            if let Ok(decoded) = frame.decode_image::<RgbFormat>() {
                let (w, h) = (decoded.width(), decoded.height());
                let buf = decoded.into_raw();
                if let Some(img) = ImageBuffer::<image::Rgb<u8>, _>::from_raw(w, h, buf) {
                    // Scale down to 640×480 if larger
                    let (nw, nh) = scale_dims(w, h, 640, 480);
                    let img = if nw != w || nh != h {
                        image::imageops::resize(&img, nw, nh, image::imageops::FilterType::Triangle)
                    } else {
                        img
                    };

                    let mut jpeg_buf = Vec::new();
                    let mut enc = JpegEncoder::new_with_quality(&mut jpeg_buf, 60);
                    if enc.encode_image(&img).is_ok() {
                        let b64 = STANDARD.encode(&jpeg_buf);
                        send(&sock, &format!("[cam_frame]{}", b64));
                    }
                }
            }
        }

        let elapsed = t0.elapsed();
        if elapsed < interval {
            thread::sleep(interval - elapsed);
        }
    }

    let _ = cam.stop_stream();
}

fn scale_dims(w: u32, h: u32, max_w: u32, max_h: u32) -> (u32, u32) {
    if w <= max_w && h <= max_h { return (w, h); }
    let scale = (max_w as f32 / w as f32).min(max_h as f32 / h as f32);
    ((w as f32 * scale) as u32, (h as f32 * scale) as u32)
}