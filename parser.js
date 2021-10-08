const fs = require('fs');
const cheerio = require('cheerio');
const request = require('sync-request');
const minimist = require('minimist')
const print = console.log
// parse args
function parse_args(argv) {
    type = argv['type'] || 'npm'
    page_to_search = Number(argv['page_count']) || 1
    out_file = argv['out'] || 'log.dat'
    start_page = Number(argv['start_page']) || 1
    sep = argv['sep'] || ','
    log_stream = fs.createWriteStream(out_file, {flags: 'w'});
    log_stream.write("Severity" + sep + "CVE" + sep + "Vulnerability" + sep + "Plugin URL" + sep +
        "Affected Plugin" + sep + "Affected Version" + sep + "Database" + sep + "Discovery Date" + sep + "#Page\n")
    filters = {}
    filters.exploit = argv['exploit']
    filters.version = argv['version']
    filters.pkg_name = argv['package']
    filters.severity = argv['severity']
    filters.date = argv['date']
}

function contain_filter(obj, filters) {
    if (filters === undefined)
        return true
    if (obj.severity !== filters.severity && filters.severity !== undefined)
        return false
    if (obj.version !== filters.version && filters.version !== undefined)
        return false
    if (obj.pkg_name != filters.pkg_name && filters.pkg_name !== undefined)
        return false
    if (obj.exploit !== filters.exploit && filters.exploit !== undefined)
        return false
    if (obj.discovery_date !== filters.date && filters.date !== undefined)
        return false
    return true
}

function write_entry(objs, filters) {
    for (let i in objs) {
        obj = objs[i]
        if (contain_filter(obj, filters) == false)
            continue;
        log_stream.write(obj.severity + sep + obj.vuln_url + sep + obj.exploit + sep + obj.plugin_url +
            sep + obj.pkg_name + sep + '"' + obj.version + '"' +
            sep + obj.database + sep + '"' + obj.discovery_date + '"' + sep + obj.page + '\n')
    }
}

// parse a page
function parse_page(pn, t) {
    let objs = []
    let url = 'https://snyk.io/vuln/page/' + pn + '?type=' + t;
    var req = request('GET', url)
    console.log("Parsing:", url)
    const $ = cheerio.load(req.body);
    $('.table--comfortable > tbody:nth-child(2)').each(function () {
        var children = $(this).children();
        for (let i = 0; i < children.length; i++) {
            //get the child
            $(children[i]).each(function () {
                let obj = {}
                var fields = $(this).children();
                let b0 = $(fields[0]).find('a')
                let b1 = $(fields[1]).find('a')
                obj.severity        = $(fields[0]).find(".severity-list__item-text").text()
                obj.vuln_url        = 'https://snyk.io' + b0.attr('href')
                obj.exploit         = b0.text().trim()
                obj.plugin_url      = 'https://snyk.io' + b1.attr('href')
                obj.pkg_name        = b1.text().trim()
                obj.version         = $(fields[1]).find(".semver").text()
                obj.database        = $(fields[2]).text().trim()
                obj.discovery_date  = $(fields[3]).text().trim()
                obj.page            = pn
                objs.push(obj)
            });
        };
    });
    return objs
};

// start parsing all the pages
function parse_all_pages(start_page, page_to_search, type, filters) {
    let page_num = start_page;
    // parse until we hit the requested number of pages
    while (page_num < page_to_search) {
        let page_entries = parse_page(page_num, type)
        write_entry(page_entries, filters)
        page_num++;
    }
}

let argv = minimist(process.argv.slice(2));
parse_args(argv)
if (filters.length === 0)
    filters = undefined
print("Applying filters:", JSON.stringify(filters))
parse_all_pages(start_page, page_to_search + start_page, type, filters)
console.log("Parsing completed");
