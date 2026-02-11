# CodeQL: Fix "Low C# analysis quality" and build-mode 'none'

The warning **"C# was extracted with build-mode set to 'none'"** and low "calls with call target" (79% &lt; 85%) happen because **GitHub Default setup** is running CodeQL without building the C# project. This repo already has a **custom workflow** that uses **manual build** for better results.

## Fix: Use only the custom workflow (Advanced setup)

Switch code scanning from **Default** to **Advanced** so only `.github/workflows/codeql.yml` runs (that workflow builds C# and gets better metrics).

### Steps

1. On GitHub, open your repo: **https://github.com/NeuroKoder3/E-SCPE**
2. Go to **Settings** (repo tab).
3. In the left sidebar, under **Security**, click **Code security and analysis**.
4. In the **Code scanning** section, find **CodeQL analysis**.
5. If it says **Default** or **Default setup**:
   - Click **⋮** (or **Edit** / **Configure**) next to CodeQL analysis.
   - Choose **Switch to advanced** (or **Disable default**).
   - In the confirmation, click **Disable CodeQL** (this only disables the *default* setup, not code scanning).
6. Confirm that **Actions** is enabled (Settings → Actions → General → "Allow all actions and reusable workflows" or as needed).
7. Our workflow **CodeQL** (`.github/workflows/codeql.yml`) will then be the only CodeQL run. It:
   - Uses **build-mode: manual**
   - Builds Rust, then C# (WinUI + tests), so CodeQL can resolve call targets
   - Should get **calls with call target** above the 85% threshold

### After switching

- Code scanning will run from **Actions** on push/PR and on the weekly schedule.
- The next run should report **build-mode: manual** and better C# analysis quality.
- To confirm: **Security** → **Code scanning** → open the latest **CodeQL** run and check the log for "Build C# (WinUI and tests)" and that it does not say "build-mode set to 'none'".
