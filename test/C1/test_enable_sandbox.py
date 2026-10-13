"""
C1 Tests - the installer's "Turn on Windows Sandbox" script
Run from project root:  python test/C1/test_enable_sandbox.py

electron/installer/enable-windows-sandbox.ps1 is what the installer runs when the user ticks the
Windows Sandbox box. These tests load its functions and replace the two Windows cmdlets that change
or read the feature with fakes, so no real feature is ever touched. What they pin down:

  * a PC that already has Windows Sandbox is never changed, and is not even asked for a state;
  * the feature is enabled only when Windows reports it as Disabled, and then exactly once;
  * a pending restart, an unsupported Windows and a refusal each have their own answer.

The last test runs the real script on this machine without elevation: where Windows Sandbox is
already on, it must answer 0 and change nothing.
"""
import os
import subprocess
import sys
import tempfile
import unittest

_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
SCRIPT = os.path.join(_ROOT, "electron", "installer", "enable-windows-sandbox.ps1")
POWERSHELL = os.path.join(os.environ.get("WINDIR", r"C:\Windows"), "System32", "WindowsPowerShell", "v1.0", "powershell.exe")


@unittest.skipUnless(sys.platform == "win32" and os.path.isfile(POWERSHELL), "needs Windows PowerShell")
class TestEnableSandboxScript(unittest.TestCase):

    def run_ps(self, body: str, launcher_present: bool = False, admin: bool = True):
        """Run `body` after loading the script's functions with the Windows cmdlets faked.
        Prints  CODE=<exit code>  GET=<times the state was read>  ENABLE=<times it was enabled>."""
        with tempfile.TemporaryDirectory(prefix="c1_sb_") as tmp:
            launcher = os.path.join(tmp, "WindowsSandbox.exe")
            if launcher_present:
                open(launcher, "wb").close()
            harness = f"""
$ErrorActionPreference = 'Stop'
. '{SCRIPT}' -NoElevate -LogFile '{os.path.join(tmp, "log.txt")}' -LauncherPath '{launcher}'
$script:getCalls = 0; $script:enableCalls = 0
function Test-IsAdministrator {{ ${str(admin).lower()} }}
function Get-WindowsOptionalFeature {{
    [CmdletBinding()] param([switch]$Online, [string]$FeatureName)
    $script:getCalls++
    if ($script:feature -eq 'Missing') {{ throw 'The feature name is unknown.' }}
    [pscustomobject]@{{ State = $script:feature }}
}}
function Enable-WindowsOptionalFeature {{
    [CmdletBinding()] param([switch]$Online, [string]$FeatureName, [switch]$All, [switch]$NoRestart)
    $script:enableCalls++
    if ($script:enableFails) {{ throw 'Error 0x800f0950' }}
    [pscustomobject]@{{ RestartNeeded = $script:restart }}
}}
{body}
$code = Invoke-SandboxSetup
Write-Output ('CODE=' + $code + ' GET=' + $script:getCalls + ' ENABLE=' + $script:enableCalls)
"""
            path = os.path.join(tmp, "harness.ps1")
            with open(path, "w", encoding="utf-8") as f:
                f.write(harness)
            out = subprocess.run([POWERSHELL, "-NoProfile", "-ExecutionPolicy", "Bypass", "-File", path],
                                 capture_output=True, text=True, timeout=60)
        line = [l for l in out.stdout.splitlines() if l.startswith("CODE=")]
        self.assertTrue(line, "harness did not finish:\n" + out.stdout + out.stderr)
        parts = dict(p.split("=") for p in line[-1].split())
        return int(parts["CODE"]), int(parts["GET"]), int(parts["ENABLE"])

    # -- already on ---------------------------------------------------------------------------------
    def test_a_pc_that_already_has_it_is_left_alone(self):
        code, get, enable = self.run_ps("$script:feature = 'Disabled'", launcher_present=True)
        self.assertEqual((code, get, enable), (0, 0, 0))      # not even asked for a state

    def test_a_pc_that_already_has_it_needs_no_administrator(self):
        code, get, enable = self.run_ps("$script:feature = 'Disabled'", launcher_present=True, admin=False)
        self.assertEqual((code, get, enable), (0, 0, 0))

    def test_windows_saying_enabled_changes_nothing(self):
        code, get, enable = self.run_ps("$script:feature = 'Enabled'")
        self.assertEqual((code, enable), (0, 0))

    # -- turning it on ------------------------------------------------------------------------------
    def test_a_disabled_feature_is_enabled_exactly_once(self):
        code, get, enable = self.run_ps("$script:feature = 'Disabled'; $script:restart = $true")
        self.assertEqual((code, enable), (11, 1))

    def test_no_restart_is_reported_when_none_is_needed(self):
        code, get, enable = self.run_ps("$script:feature = 'Disabled'; $script:restart = $false")
        self.assertEqual((code, enable), (12, 1))

    def test_running_it_twice_does_not_enable_twice(self):
        # the second run sees what the first one left behind: a feature waiting for a restart
        first = self.run_ps("$script:feature = 'Disabled'; $script:restart = $true")
        second = self.run_ps("$script:feature = 'EnablePending'")
        self.assertEqual((first[0], first[2]), (11, 1))
        self.assertEqual((second[0], second[2]), (10, 0))

    # -- states that must not be changed ------------------------------------------------------------
    def test_a_pending_restart_is_not_enabled_again(self):
        self.assertEqual(self.run_ps("$script:feature = 'EnablePending'")[::2], (10, 0))

    def test_a_different_pending_change_is_not_touched(self):
        self.assertEqual(self.run_ps("$script:feature = 'DisablePending'")[::2], (31, 0))

    def test_an_unknown_state_is_not_touched(self):
        self.assertEqual(self.run_ps("$script:feature = 'SomethingNew'")[::2], (20, 0))

    # -- cannot be done -----------------------------------------------------------------------------
    def test_windows_without_the_feature_is_reported_not_forced(self):
        self.assertEqual(self.run_ps("$script:feature = 'Missing'")[::2], (20, 0))

    def test_a_refusal_from_windows_is_reported(self):
        self.assertEqual(self.run_ps("$script:feature = 'Disabled'; $script:enableFails = $true")[::2], (30, 1))

    def test_without_administrator_rights_nothing_is_attempted(self):
        self.assertEqual(self.run_ps("$script:feature = 'Disabled'", admin=False), (40, 0, 0))

    # -- the real script on this machine ------------------------------------------------------------
    def test_the_real_script_here(self):
        launcher = os.path.join(os.environ.get("WINDIR", r"C:\Windows"), "System32", "WindowsSandbox.exe")
        out = subprocess.run([POWERSHELL, "-NoProfile", "-ExecutionPolicy", "Bypass", "-File", SCRIPT, "-NoElevate",
                              "-LogFile", os.path.join(tempfile.gettempdir(), "c1_sb_real_test.log")],
                             capture_output=True, text=True, timeout=60)
        if os.path.isfile(launcher):
            self.assertEqual(out.returncode, 0, out.stdout + out.stderr)
            self.assertIn("already enabled", out.stdout.lower())
        else:
            self.assertEqual(out.returncode, 40, out.stdout + out.stderr)     # not on, and no administrator here


if __name__ == "__main__":
    unittest.main(verbosity=1)
