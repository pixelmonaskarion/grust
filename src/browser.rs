use headless_chrome::{Browser, LaunchOptionsBuilder};

pub async fn open_browser() {
    let browser = Browser::new(LaunchOptionsBuilder::default().headless(false).build().unwrap()).unwrap();

    let tab = browser.new_tab().unwrap();

    // Navigate to wikipedia
    tab.navigate_to("https://accounts.google.com").unwrap();
    tab.wait_for_xpath("https://myaccount.google.com/*").unwrap();
}