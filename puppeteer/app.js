const puppeteer = require('puppeteer');

const escapeXpathString = str => {
    const splitedQuotes = str.replace(/'/g, `', "'", '`);
    return `concat('${splitedQuotes}', '')`;
  };

const clickByText = async (page, text) => {
    const escapedText = escapeXpathString(text);
    const linkHandlers = await page.$x(`//a[contains(text(), ${escapedText})]`);
    
    if (linkHandlers.length > 0) {
      await linkHandlers[0].click();
    } else {
      throw new Error(`Link not found: ${text}`);
    }
  };

(async () => {
	const browser = await puppeteer.launch({headless: false});
	const page = await browser.newPage();
	await page.goto(process.env.QUAY_URL);

  await clickByText(page, `Create Account`);
  await page.waitForSelector('input[placeholder="Requested username"]');
  await page.type('input[placeholder="Requested username"]', process.env.QUAY_USERNAME, {delay: 100});
  await page.type('input[placeholder="Your email address"]', process.env.QUAY_EMAIL);
  await page.type('input[placeholder="Create a password"]', process.env.QUAY_PASSWORD);
  await page.type('input[placeholder="Verify your password"]', process.env.QUAY_PASSWORD); 
  
  await page.click('button[id="signupButton"]');

	await browser.close();
})();
