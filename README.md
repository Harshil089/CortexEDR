# CortexEDR

Windows Endpoint Detection & Response system built in C++20 with a Qt6 GUI. Monitors process, file, network, and registry activity in real-time using native Windows APIs.

![Platform](https://img.shields.io/badge/platform-Windows%2010%2F11-blue)
![C++](https://img.shields.io/badge/C%2B%2B-20-orange)
![Qt](https://img.shields.io/badge/Qt-6-green)

---

## Prerequisites

- **Windows 10/11** (x64)
- **Visual Studio 2022** with "Desktop development with C++" workload
- **CMake 3.20+** (comes with VS 2022)
- **Administrator privileges** (for ETW monitoring)

---

## Build from Scratch

### Step 1: Install vcpkg

```powershell
git clone https://github.com/Microsoft/vcpkg.git C:\vcpkg
cd C:\vcpkg
.\bootstrap-vcpkg.bat
.\vcpkg integrate install
```

### Step 2: Install dependencies

```powershell
C:\vcpkg\vcpkg install yaml-cpp:x64-windows nlohmann-json:x64-windows spdlog:x64-windows gtest:x64-windows openssl:x64-windows sqlite3:x64-windows
```

### Step 3: Install Qt6

Download from [qt.io/download](https://www.qt.io/download). During installation, select **Qt 6.x → MSVC 2022 64-bit**.

Default install path: `C:\Qt\6.x.x\msvc2022_64` (replace `6.x.x` with your version).

### Step 4: Configure

```powershell
cd C:\Lightweight-Windows-EDR-System

cmake -B build -S . -DCMAKE_TOOLCHAIN_FILE=C:\vcpkg\scripts\buildsystems\vcpkg.cmake -DCMAKE_PREFIX_PATH="C:\Qt\6.x.x\msvc2022_64" -DBUILD_GUI=ON
```

### Step 5: Build everything

```powershell
cmake --build build --config Debug
```

This produces:

- `build\Debug\CortexEDR.exe` — Console backend engine
- `build\Debug\CortexEDR_GUI.exe` — Qt6 GUI application
- `build\Debug\cortex_tests.exe` — Unit tests

Qt DLLs and the stylesheet are auto-copied to `build\Debug\` by CMake post-build steps.

---

## Running

### Start the backend (requires Admin)

```powershell
# Open PowerShell as Administrator
.\build\Debug\CortexEDR.exe
```

This starts all monitors (Process, File, Network, Registry) and the detection engine. Press `Ctrl+C` to stop.

### Start the GUI

```powershell
.\build\Debug\CortexEDR_GUI.exe
```

The GUI connects to the backend via shared memory/named pipes. Dashboard shows connection status.

### Run tests

```powershell
.\build\Debug\cortex_tests.exe
```

---

## After Pushing New Changes

When you pull or push new changes and need to rebuild:

```powershell
cd C:\Lightweight-Windows-EDR-System

# Reconfigure (only needed if CMakeLists.txt changed)
cmake -B build -S . -DCMAKE_TOOLCHAIN_FILE=C:\vcpkg\scripts\buildsystems\vcpkg.cmake -DCMAKE_PREFIX_PATH="C:\Qt\6.x.x\msvc2022_64" -DBUILD_GUI=ON

# Rebuild
cmake --build build --config Debug

# Run backend (Admin PowerShell)
.\build\Debug\CortexEDR.exe

# Run GUI (separate terminal)
.\build\Debug\CortexEDR_GUI.exe
```

If only `.cpp`/`.hpp` files changed, skip the configure step — just rebuild:

```powershell
cmake --build build --config Debug
```

---

## Build Without GUI

If you don't have Qt6 installed:

```powershell
cmake -B build -S . -DCMAKE_TOOLCHAIN_FILE=C:\vcpkg\scripts\buildsystems\vcpkg.cmake -DBUILD_GUI=OFF
cmake --build build --config Debug
```

---

## Project Structure

```
CortexEDR/
├── core/           EventBus, ThreadPool, Logger
├── collectors/     ProcessMonitor (ETW), FileMonitor, NetworkMonitor, RegistryMonitor
├── engine/         RiskScorer, RuleEngine, BehaviorCorrelator
├── response/       ContainmentManager, IncidentManager
├── compliance/     AuditLogger, MitreMapper, ComplianceReporter, ForensicsExporter
├── telemetry/      TelemetryExporter (JSON export)
├── ipc/            SharedMemory + NamedPipe IPC
├── persistence/    SQLite database manager
├── ui/             Qt6 GUI (all panels + EDRBridge adapter)
├── tests/          Unit tests (GTest)
├── config/         config.yaml, rules.yaml
├── main.cpp        Console engine entry point
└── main_gui.cpp    GUI entry point
```

---

## Troubleshooting

**ETW "Access Denied"** — Run as Administrator.

**"NT Kernel Logger" already in use** — Another ETW consumer is active:

```powershell
logman stop "NT Kernel Logger" -ets
```

**Qt6 not found during configure** — Check your `CMAKE_PREFIX_PATH` matches the actual Qt install path.

**GUI missing DLLs** — The `windeployqt` post-build step should handle this automatically. If not:

```powershell
C:\Qt\6.x.x\msvc2022_64\bin\windeployqt6.exe .\build\Debug\CortexEDR_GUI.exe
```

---

## Configuration

Edit `config/config.yaml`:

```yaml
risk_scoring:
  thresholds:
    low: 30
    medium: 60
    high: 80
    critical: 100

file_monitoring:
  watch_paths:
    - C:\Users
    - C:\Windows\System32

network_monitoring:
  poll_interval_seconds: 2
  suspicious_ports: [4444, 1337, 6667]
```

---

## License

MIT

## Disclaimer

Educational prototype for portfolio demonstration. Not for production use without security hardening.
