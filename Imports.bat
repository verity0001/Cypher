@echo off
set PYTHON_PACKAGES="tkinter" "pycryptodome"
set PIP_COMMAND=pip install
set DOWNLOAD_COMMAND=%PIP_COMMAND% %PYTHON_PACKAGES%
echo Installing required Python packages...
%DOWNLOAD_COMMAND%
echo Finished installing Python packages.
pause