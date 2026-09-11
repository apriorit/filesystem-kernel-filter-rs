use time::macros::format_description;
use winresource::WindowsResource;

fn get_current_time() -> anyhow::Result<String> {
    let format = format_description!("[year]-[month]-[day]T[hour]-[minute]-[second]");

    Ok(time::OffsetDateTime::now_utc().format(&format)?)
}

fn main() -> anyhow::Result<()> {
    println!("cargo:rustc-env=BUILD_TIME={}", get_current_time()?);

    WindowsResource::new().compile()?;

    // The minifilter APIs (Flt*) are exported by fltMgr.lib, which wdk-build
    // does not emit a link directive for.
    println!("cargo:rustc-link-lib=static=fltMgr");

    Ok(wdk_build::configure_wdk_binary_build()?)
}
