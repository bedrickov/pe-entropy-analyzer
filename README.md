# PEGuard

<div align="center">

![Platform](https://img.shields.io/badge/Platform-Windows%20(x64)-0078D4?style=flat-square&logo=windows)
![Language](https://img.shields.io/badge/Language-C%23%2013%20%2F%20.NET%2010-512BD4?style=flat-square&logo=dotnet)
![License](https://img.shields.io/badge/License-MIT-blue?style=flat-square)
![Build](https://img.shields.io/badge/Build-Passing-brightgreen?style=flat-square)

**Высокоскоростной анализатор структуры PE32/PE32+ заголовков и энтропии секций.**  
*Детекция обфусцированных, упакованных (UPX, VMProtect, Themida) и криптованных секций исполняемых файлов Windows.*

</div>

---

## Возможности

- Мгновенный парсинг DOS-заголовка (`e_lfanew`) и таблицы NT Headers (PE Signature, File Header, Section Table).
- Расчет энтропии Шеннона с побайтовым анализом для каждой секции (`.text`, `.rdata`, `.data`, `.rsrc`).
- Определение подозрительных секций с аномально высокой энтропией (> 7.2) или несоответствием физического и виртуального размеров.

## Сборка и запуск

```powershell
dotnet build -c Release
.\bin\Release\net10.0\PEGuard.exe <path_to_binary>
```

## Лицензия
MIT

<!-- verified: 2026-10-30 -->