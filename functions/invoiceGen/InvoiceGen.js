const fs = require('fs');
const path = require('path');
const hbs = require('handlebars');
const puppeteer = require('puppeteer');


const compile = async function (templateName, data) {
    const filePath = path.join(__dirname, `./views/` + `${templateName}.hbs`);

    const html = await fs.promises.readFile(filePath, 'utf-8');

    const template = hbs.compile(html)
    return template(data);
};

hbs.registerHelper('dateFormat', function (value, format) {
    return moment(value).format(format);
});

const getAllData = (userGivenData) => {

    let array = [];

    userGivenData.invoiceItems.forEach(d => {

        const prod = {
            name: d.description,
            description: d.comment,
            quantity: Number(d.qty),
            price: Number(d.price),
            total: Number(d.total)
        }
        array.push(prod);
    });

    const date = new Date(userGivenData.invoice_date);
    const formatted_date = date.toISOString().split('T')[0];

    const CompleteData = {
        wo_number: userGivenData.woNumber,
        date: formatted_date,

        credit_Memo: userGivenData.credit_Memo ? "Yes" : "No",
        invoice_Complete: userGivenData.invoice_Complete ? "Yes" : "No",
        reference_ID: userGivenData.Reference_ID,
        head_comment: userGivenData.Head_Comment,

        prodlist: array,

        subtotal: Number(userGivenData.Sub_Total),
        discount: Number(userGivenData.Discount),
        gtotal: Number(userGivenData.Total),
    }

    console.log(CompleteData);

    return CompleteData;
}

// Main Part
async function invoiceGen(userGivenData, acceptorClient) {
    try {
        const browser = await puppeteer.launch();
        const page = await browser.newPage();

        const data = getAllData(userGivenData);
        let content;

        if (acceptorClient) {
            content = await compile('client_invoice', data);
        } else {
            content = await compile('contractor_invoice', data);
        }

        await page.setContent(content);
        await page.emulateMediaType('screen');

        const thePdf = await page.pdf({
            format: 'A4',
            printBackground: true
        });

        console.log("done");

        await browser.close();

        return thePdf;
    } catch (error) {
        console.error(error);
    }
};

module.exports = {
    invoiceGen
}