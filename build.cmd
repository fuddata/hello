@echo off
mkdir dist
del /q hello.msix
go build -o dist\hello.exe
copy /y AppxManifest.xml dist
copy /y logo.png dist
rem Add-AppxPackage -Register dist\AppxManifest.xml
makeappx.exe pack /v /d dist /p hello.msix
SignTool sign /fd sha256 /n "Fuddata Limited" hello.msix
