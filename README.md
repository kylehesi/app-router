# Router: uygulama bazlı internet seçici (Windows)

Bilgisayara aynı anda birden fazla internet bağlıyken (dahili Wi-Fi, USB Wi-Fi, telefondan
USB tethering, Ethernet...) her uygulamanın hangi internetten çıkacağını seçmenizi sağlar.

> **Donanım şartı:** Her internet bağlantısı için ayrı bir ağ adaptörü gerekir. Tek bir Wi-Fi
> kartı aynı anda yalnızca bir ağa bağlanabilir.

## Mimari

```
┌──────────────┐  named pipe (JSON)  ┌────────────────────────────────────────────┐
│ router-ui    │ ◄─────────────────► │ router-service  (Windows servisi, SYSTEM)  │
│ Slint, Rust  │                     │  ├ ipc     : arayüzle iletişim             │
│ normal yetki │                     │  ├ rules   : exe → adaptör GUID kuralları  │
└──────────────┘                     │  └ engine  : TUN + yönlendirme (Faz 2)     │
                                     └────────────────────────────────────────────┘
```

| Crate | Görev |
|---|---|
| `crates/common` | Ortak tipler ve IPC protokolü |
| `crates/sys` | Windows API: adaptörler + SSID, süreçler, soket→PID tabloları, yetki, politika |
| `crates/engine` | Wintun TUN, paket ayrıştırma, soketleri adaptöre bağlama (`IP_UNICAST_IF`) |
| `crates/service` | Arka plan servisi + tanılama komutları |
| `crates/ui` | Masaüstü arayüzü |

**Neden bu yapı?**
- **Sürücü imzası gerekmez:** Wintun'u WireGuard ekibi imzalamıştır ve exe'nin yanında dağıtılır.
- **Rust:** Çöp toplayıcı (GC) duraklaması olmadan C/C++ hızında çalışır, bellek güvenlidir.
- **TCP'yi Windows'un kendi yığını yönetir** ("system stack" NAT). Pencereleme ve tıkanıklık
  kontrolü Windows'ta kalır; uygulama yalnızca baytları seçilen adaptöre aktarır.
- Çalışma zamanı exe'ye gömülüdür (`crt-static`), ayrıca VC++ Redistributable kurmak gerekmez.

## Gereksinimler

- Windows 10/11 x64
- Visual Studio 2022 Build Tools (C++ ve Windows SDK)
- Rust (stable, MSVC)

## Derleme ve çalıştırma

```powershell
cargo build --release
powershell -ExecutionPolicy Bypass -File scripts\fetch-wintun.ps1
```

Geliştirme sırasında servisi konsolda çalıştırmak (yönetici terminali):

```powershell
target\release\router-service.exe run
target\release\router-ui.exe
```

Kalıcı kurulum (bilgisayar açılınca otomatik başlar, çökerse kendini yeniden başlatır):

```powershell
target\release\router-service.exe install
```

## Tanılama komutları

```powershell
router-service adapters        # adaptörler, SSID'ler, IP'ler, ağ geçitleri
router-service apps            # ağ kullanan uygulamalar
router-service probe "Wi-Fi"   # bu adaptör üzerinden dış IP'yi göster
router-service doctor          # sistem hazır mı?
router-service tun-test        # Wintun çalışıyor mu? (yönetici)
```

Kurallar `%ProgramData%\Router\rules.json`, servis günlüğü `%ProgramData%\Router\service.log` dosyasında tutulur.

## Yol haritası

- [x] **Faz 1, iskelet:** adaptör ve SSID listesi, uygulama listesi, kural saklama, IPC, Windows
      servisi, arayüz, adaptöre bağlı soketler, Wintun açma
- [ ] **Faz 2, veri yolu:** TUN rota yönetimi, TCP "system stack" NAT ve aktarma, UDP oturumları,
      DNS yönetimi, soket→süreç eşleme önbelleği
- [ ] **Faz 3, kullanım kolaylığı:** sistem tepsisi simgesi, adaptör kopunca yedek bağlantıya geçiş,
      adaptör başına hız grafiği, alt süreçlerin kuralı devralması, MSI kurulum paketi
