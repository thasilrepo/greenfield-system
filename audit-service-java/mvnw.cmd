@echo off
setlocal
set MVNW_DIR=%~dp0
set WRAPPER_DIR=%MVNW_DIR%\.mvn\wrapper
set WRAPPER_JAR=%WRAPPER_DIR%\maven-wrapper.jar
if not exist "%WRAPPER_JAR%" (
  echo Maven wrapper JAR not found in %WRAPPER_JAR%
  echo To bootstrap the wrapper, run: mvn -N io.takari:maven:wrapper
  exit /b 1
)
java -jar "%WRAPPER_JAR%" %*
