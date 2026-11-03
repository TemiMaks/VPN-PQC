# Tunel VPN (TUN + UDP) — Notatki i Testowanie

### Po co w ogóle jest ten interfejs TUN?
Zwykły program sieciowy (np. przeglądarka) nie ma bezpośredniego dostępu do tworzenia surowych pakietów IP dla innych aplikacji. 

Interfejs **TUN (`/dev/net/tun`)** udaje przed systemem fizyczną kartę sieciową (działa w warstwie 3 — IP). Dzięki niemu:
* System myśli, że ma wpięty nowy kabel sieciowy i wysyła pakiety na podany adres (np. `10.8.0.x`).
* Zamiast na kabel, te pakiety trafiają wprost do pliku w naszym programie w Go.
* Program może zrobić z tymi bajtami cokolwiek (zaszyfrować, zmierzyć, przepakować) i wysłać je dalej zwykłym internetem przez UDP.

---

### Jak to w skrócie działa?

```
[ Twoja aplikacja / ping ]
          │ (pakiety IP)
          ▼
      ┌───────┐
      │  tun  │ (wirtualna karta sieciowa w Linuksie)
      └───┬───┘
          │ czytamy/piszemy jak ze zwykłego pliku
          ▼
   ┌─────────────┐
   │ nasz demon  │ (Go: main.go)
   └──────┬──────┘
          │ surowe ramki UDP (port 9999)
          ▼
     [ Internet / Sieć ]
```

1. **Klient:** `ping 10.8.0.1` generuje pakiet IP $\to$ pakiet wpada do wirtualnego interfejsu `tun1` $\to$ program Go go odczytuje $\to$ pakuje w zwykłe UDP i śle na adres serwera.
2. **Serwer:** Demon Go odbiera ramkę UDP $\to$ wyciąga z niej czysty pakiet IP $\to$ wstrzykuje go do swojego `tun0` $\to$ jądro Linuksa widzi swój adres `10.8.0.1` i generuje odpowiedź (Echo Reply) $\to$ serwer odsyła odpowiedź przez UDP $\to$ klient odbiera i wstrzykuje do swojego `tun1`.

---

### Jak to skompilować?

W głównym katalogu projektu:
```bash
go build -o vpn-daemon .
```

---

### Przykład uruchomienia i test na 1 maszynie (WSL 2)

Żeby przetestować klienta i serwer na jednym komputerze bez konfliktów sieciowych, tworzymy osobną przestrzeń nazw (`client-ns`) połączoną wirtualnym kablem (`veth`):

#### Krok 0: Przygotowanie sieci (wykonaj raz w terminalu)
```bash
sudo ip netns add client-ns
sudo ip link add veth-host type veth peer name veth-client
sudo ip link set veth-client netns client-ns

sudo ip addr add 192.168.100.1/24 dev veth-host
sudo ip link set veth-host up

sudo ip netns exec client-ns ip addr add 192.168.100.2/24 dev veth-client
sudo ip netns exec client-ns ip link set veth-client up
sudo ip netns exec client-ns ip link set lo up
```

#### Terminal 1 — Serwer
Odpala serwer na hoście:
```bash
sudo ./vpn-daemon -mode=server -port=9999 -tun=tun0
```

#### Terminal 2 — Klient
Odpala klienta w wyizolowanej przestrzeni:
```bash
sudo ip netns exec client-ns ./vpn-daemon -mode=client -server="192.168.100.1:9999" -tun=tun1
```

#### Terminal 3 — Test (Ping przez tunel)
Wysyłamy ruch przez wirtualne IP tunelu:
```bash
sudo ip netns exec client-ns ping -c 4 10.8.0.1
```

**Wynik sukcesu:** Pakiety wracają z czasem ~1 ms i 0% strat:
```text
64 bytes from 10.8.0.1: icmp_seq=1 ttl=64 time=0.584 ms
...
4 packets transmitted, 4 received, 0% packet loss
```

---

### Sprzątanie po testach
Zatrzymaj demony (`Ctrl+C` w obu oknach), a następnie usuń namespace:
```bash
sudo ip netns del client-ns
```
*(Interfejsy `tun0` i `tun1` znikają same natychmiast po zamknięciu programów).*