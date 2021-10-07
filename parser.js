const fs = require('fs');
const cheerio = require('cheerio');
const request = require('sync-request');
const minimist = require('minimist')
let type = 'npm'
let page_to_search = 1;
let out_file = 'log.dat';
let sep = undefined
let write_headers = false
let start_page = 1
// parse args
function parse_args(argv) {
    if (argv['type'] != undefined)
        type = argv['type']
    if (argv['page_count'] != undefined)
        page_to_search = Number(argv['page_count'])
    if (argv['out'] != undefined)
        out_file = argv['out']
    if (argv['sep'] != undefined)
        sep = argv['sep']
    if (argv['start_page'] != undefined)
        start_page = Number(argv['start_page'])
    log_stream = fs.createWriteStream(out_file, {flags: 'w'});
    if (argv['write_headers']) {
        log_stream.write("Severity" + sep + "CVE" + sep + "Vulnerability" + sep + "Plugin URL" + sep +
            "Affected Plugin" + sep + "Affected Version" + sep + "Database" + sep + "Discovery Date" + sep + "#Page\n")
    }
}

function write_entry(obj) {
    if (sep == undefined) 
        log_stream.write(JSON.stringify(obj) + '\n')
    else 
        log_stream.write(obj.severity + sep + obj.vuln_url + sep + obj.type + sep + obj.plugin_url +
            sep + obj.affected_plugin + sep + '"' + obj.plugin_version + '"' +
            sep + obj.database + sep + '"' + obj.discovery_date + '"' + sep + obj.page + '\n')
}

// parse a page
function parse_page(pn, t) {
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
                obj.severity = $(fields[0]).find(".severity-list__item-text").text()
                obj.vuln_url = 'https://snyk.io' + b0.attr('href')
                obj.type     = b0.text().trim()
                obj.plugin_url         = 'https://snyk.io' + b1.attr('href')
                obj.affected_plugin    = b1.text().trim()
                obj.plugin_version = $(fields[1]).find(".semver").text()
                obj.database = $(fields[2]).text().trim()
                obj.discovery_date = $(fields[3]).text().trim()
                obj.page = pn
                write_entry(obj)
            });
        }
    });
}

// start parsing all the pages
function parse_all_pages(sp, p2s, t) {
    let page_num = sp;
    // parse until we hit the requested number of pages
    while (page_num < p2s) {
        parse_page(page_num, t)
        page_num++;
    }
}

let argv = minimist(process.argv.slice(2));
parse_args(argv)
parse_all_pages(start_page, page_to_search + start_page, type)
console.log("Parsing completed");
