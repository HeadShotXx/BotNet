# PIC Loader - Gelişmiş Yansıtıcı Yükleyici (Reflective Loader)

Bu proje, bir Windows çalıştırılabilir dosyasını (EXE) başka bir C dosyası içine gömerek, bellek üzerinden yansıtıcı bir şekilde yüklenmesini sağlayan bir araçtır. Gelişmiş IAT (Import Address Table) onarma özelliği sayesinde Forwarded Export'ları ve modern Windows API Set Schema (api-ms-win-core-...) yapılarını manuel olarak çözebilir.

## Özellikler

*   **API Set Schema Desteği:** `ApiSetMap` üzerinden manuel yönlendirme çözümü (v6).
*   **Forwarded Export Desteği:** `KERNEL32.Sleep` -> `NTDLL.NtDelayExecution` gibi yönlendirmeleri recursive olarak çözer.
*   **x64 İstisna Yönetimi:** `RtlAddFunctionTable` ile 64-bit exception desteği.
*   **TLS Callback Desteği:** Thread Local Storage geri çağırmalarını çalıştırır.
*   **Bellek Korumaları:** Bölüm karakteristiklerine göre (RWX) doğru `VirtualProtect` ayarları.
*   **PIC Dostu:** CRT bağımlılığı olmayan yardımcı fonksiyonlar.

## Derleme ve Kullanım Talimatları

### 1. Hazırlık Araçlarını Derleyin

Öncelikle, payload dosyanızı yükleyici şablonuna gömecek olan builder aracını derlemeniz gerekir.

**Windows (MinGW/GCC):**
```bash
gcc exe_to_embedded_loader.c -o exe_to_embedded_loader.exe
```

**Linux (Cross-compile):**
```bash
x86_64-w64-mingw32-gcc exe_to_embedded_loader.c -o exe_to_embedded_loader.exe
```

### 2. Payload'u Gömün ve Yükleyiciyi Oluşturun

Payload olarak kullanmak istediğiniz EXE dosyasını seçin (örneğin `payload.exe`).

```bash
./exe_to_embedded_loader.exe payload.exe
```

Bu komut, geçerli dizinde `final_loader.c` adında yeni bir dosya oluşturacaktır. Bu dosya, payload'unuzun hex dizisi halini ve onu yüklemek için gereken tüm mantığı içerir.

### 3. Final Yükleyiciyi Derleyin

Şimdi oluşturulan `final_loader.c` dosyasını gerçek bir Windows çalıştırılabilir dosyası haline getirin.

**Windows (MinGW/GCC):**
```bash
gcc final_loader.c -o final_loader.exe -lkernel32 -luser32
```

**MSVC (Developer Command Prompt):**
```bash
cl.exe final_loader.c /Fe:final_loader.exe /link kernel32.lib user32.lib
```

## Notlar

*   Derlenen `final_loader.exe` çalıştırıldığında, içine gömülen `payload.exe` dosyasını belleğe açacak, importlarını manuel olarak onaracak ve giriş noktasından (Entry Point) başlatacaktır.
*   Bu yükleyici, payload'un diskte bulunmasına gerek duymadan bellek üzerinden çalışmasını sağlar.
