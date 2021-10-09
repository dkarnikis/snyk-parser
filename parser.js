const fs = require('fs');
const cheerio = require('cheerio');
const request = require('sync-request');
const minimist = require('minimist')
const get_dependencies = require('get-dependencies');
const print = console.log

let db_url = 'https://npmjs.com/package/'
let index = 0
// dependants
let deps_count = {};
let exploit_count = {};
let dependencies_count = {};
let objs = []
// parse args
function parse_args(argv) {
    type = argv['type'] || 'npm'
    page_to_search = Number(argv['page_count']) || 1
    out_file = argv['out'] || 'log.dat'
    start_page = Number(argv['start_page']) || 1
    sep = argv['sep'] || ','
    log_stream = fs.createWriteStream(out_file, {flags: 'w'});
    log_stream.write("Severity" + sep + "CVE" + sep + "Vulnerability" + sep + "Plugin URL" + sep +
        "Affected Plugin" + sep + "Affected Version" + sep + "Database" + sep + "Discovery Date" 
        + sep + "#Dependents" + sep + "#Page" + sep + "Id" + sep + "C_BUG" + sep + "Dependencies\n")
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

function write_entry(obj) {
    if (contain_filter(obj, filters) == false)
        return 
    log_stream.write(obj.severity + sep + obj.vuln_url + sep + obj.exploit + sep + obj.plugin_url +
        sep + obj.pkg_name + sep + '"' + obj.version + '"' +
        sep + obj.database + sep + '"' + obj.discovery_date + '"' + sep + 
        obj.dependents + sep + obj.page + sep + obj.id +  sep + obj.c_bug + sep + obj.dependencies +'\n')
}

// fetch the dependents if they do not exist in the hashmap
function get_dependents(pkg_name) {
    var db_req = request('GET', db_url + pkg_name)
    const db_xd = cheerio.load(db_req.body)
    return db_xd('#package-tab-dependents > span:nth-child(1)').text().replace(',', '').replace("Dependents", "")
}

function dependencies(pkg_name) {
    let res = "Failed to fetch deps"
    try {
        res = get_dependencies.getByName(pkg_name).then(function(result) {
            return result
        });
    } 
    catch (error) {
        print("Error")
    }
    return res
}

async function iterate_child($, ctx, child, pn, index) {
    let obj = {}
    var fields = $(ctx).children();
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
    obj.id = index
    obj.dependents = deps_count[obj.pkg_name] || get_dependents(obj.pkg_name)
    deps_count[obj.pkg_name] = obj.dependents
    exploit_count[obj.exploit] = (exploit_count[obj.exploit] +1) || 1
    dependencies(obj.pkg_name).then(function(result) {
        obj.dependencies = dependencies_count[obj.pkg_name] || '"' + result + '"'
        dependencies_count[obj.pkg_name] = obj.dependencies
        obj.c_bug = 'no'
        if (result.indexOf('nan') != -1)
            obj.c_bug = 'nan'
        else if (result.indexOf('napi-macros') != -1)
            obj.c_bug = 'napi-macros'
        else if (result.indexOf('node-addon-api') != -1)
            obj.c_bug = 'node-addon-api'
        write_entry(obj)
    })
}

function iterate_children($, children, pn) {
    let len = children.length
    for (let i = 0; i < len; i++) {
        //get the child
        $(children[i]).each(function () {
            iterate_child($, this, children[i], pn, index++)
        })
    }
}

// parse a page
function parse_page(pn, t) {
    let url = 'https://snyk.io/vuln/page/' + pn + '?type=' + t;
    var req = request('GET', url)
    console.log("Parsing:", url)
    const $ = cheerio.load(req.body)
    $('.table--comfortable > tbody:nth-child(2)').each(function () {
        var children = $(this).children();
        iterate_children($, children, pn);
    })
}

// start parsing all the pages
function parse_all_pages(start_page, page_to_search, type) {
    let page_num = start_page
    // parse until we hit the requested number of pages
    while (page_num < page_to_search) {
        parse_page(page_num++, type)
    }
}

let argv = minimist(process.argv.slice(2));
parse_args(argv)
if (filters.length === 0)
    filters = undefined
print("Applying filters:", JSON.stringify(filters))
parse_all_pages(start_page, page_to_search + start_page, type)
console.log("Parsing completed");
for (let i in exploit_count) {
    print(i +":" + exploit_count[i])
}
