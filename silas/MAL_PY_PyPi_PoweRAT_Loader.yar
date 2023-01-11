rule MAL_PY_PyPi_PoweRAT_Loader
{
	meta:
		author = "Silas Cutler"
		description = "Detection for PoweRAT loader used on PyPi"
		date = "2023-01-11"
		version = "1.0"
		ref = "https://blog.phylum.io/a-deep-dive-into-powerat-a-newly-discovered-stealer/rat-combo-polluting-pypi"
		DaysofYARA = "11/100"

	strings:
		$b64_enc_func = "ZGVmIHJ1bihjbWQpOmltcG9ydCB"
		$printmsg = "Installing dependencies, please wait..."
		$ps = "powershell -command $ProgressPreference = 'SilentlyContinue'"
		$wscript = " C:\\ProgramData\\Updater\\launch.vbs"

		$py_setup01 = "setup("
		$py_setup02 = "Programming Language :: Python"

	condition:
		all of ($py_setup*) and ($b64_enc_func or $printmsg or $ps or $wscript)
}
