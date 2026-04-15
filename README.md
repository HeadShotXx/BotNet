# PIC Loader (Zero-Dependency Reflective PE Loader)

Bu proje, bir Windows PE (Portable Executable) dosyasını başka bir taşıyıcı (container) içine gömen ve çalışma zamanında bellekte çözen, sıfır bağımlılıklı (zero-dependency) bir yansıtıcı yükleyici (Reflective Loader) projesidir.

## Özellikler

*   **Sıfır Windows API Bağımlılığı:** Yükleyici (`loader_template.c`), `#include <windows.h>` kullanmaz. Tüm gerekli yapıları ve fonksiyonları (PEB üzerinden) çalışma zamanında kendisi çözer.
*   **Gelişmiş Import Çözümleme (Import Fix):**
    *   **Forwarded Exports:** `KERNEL32.Sleep` -> `NTDLL.NtDelayExecution` gibi yönlendirilmiş exportları rekürsif olarak çözer.
    *   **API Set Schema Support:** `api-ms-win-core...` gibi DLL adlarını Windows 10+ API Set haritalamasını (v6) manuel parse ederek gerçek DLL'lere yönlendirir.
    *   **LdrGetProcedureAddress & LdrLoadDll:** Standart `GetProcAddress` yerine düşük seviyeli NTDLL fonksiyonlarını kullanarak daha gizli ve güvenli yükleme sağlar.
*   **PIC (Position Independent Code):** Yükleyici kodu konumdan bağımsızdır ve herhangi bir CRT (C Runtime) bağımlılığı yoktur.
*   **TLS Callback Desteği:** Yüklenecek PE içindeki TLS callback fonksiyonlarını düzgün bir şekilde çalıştırır.
*   **Exception Handling:** x64 üzerinde `RtlAddFunctionTable` ile exception handling kaydını yapar.

## Kullanım

### 1. Builder'ı Derleme

Önce bir EXE'yi yükleyici içine gömecek olan builder aracını derleyin:

**Linux (Cross-Compile):**
```bash
gcc exe_to_embedded_loader.c -o exe_to_embedded_loader
```

**Windows (MinGW):**
```bash
gcc exe_to_embedded_loader.c -o exe_to_embedded_loader.exe
```

### 2. Payload Oluşturma

İstediğiniz bir Windows EXE dosyasını yükleyici ile birleştirin:

```bash
./exe_to_embedded_loader target_app.exe final_loader.c
```

### 3. Final Loader'ı Derleme

Oluşan `final_loader.c` dosyasını hedef mimariye göre derleyin. **Not:** Loader sıfır bağımlılıklı olduğu için herhangi bir Windows kütüphanesine (`-lkernel32` vb.) bağlamanıza gerek yoktur.

**Windows (MinGW - x64):**
```bash
gcc -m64 -O2 -fno-stack-protector -nodefaultlibs -nostdlib final_loader.c -o loader.exe -lntdll -luser32
```
*(Not: `mainCRTStartup` vb. eksikliği için basit bir wrapper kullanılabilir veya `-e main` ile giriş noktası belirtilebilir. Tamamen bağımsız bir shellcode olarak kullanmak için `-c` ile object dosyası üretilip shellcode extract edilebilir.)*

**Hızlı Test İçin (Standard Derleme):**
```bash
gcc final_loader.c -o loader.exe
```

## Teknik Detaylar

*   **PEB Çözümleme:** `READ_PEB()` makrosu ile GS/FS registerları üzerinden Process Environment Block'a erişilir.
*   **Bootstrapping:** Yükleyici çalışmaya başladığında önce kendi içindeki `get_module_base_manual` ile `ntdll.dll`'in adresini bulur, ardından gerekli temel NT fonksiyonlarını (`NtAllocateVirtualMemory` vb.) manuel olarak çözer.
*   **Import Fix:** Payload'un import tablosundaki her DLL, API Set Schema kontrolünden geçirilerek doğru modül yüklenir.

## Uyarılar

*   Bu araç eğitim ve araştırma amaçlıdır.
*   Yüklenecek EXE'nin mimarisi (x86/x64) ile yükleyicinin derlendiği mimari aynı olmalıdır.
