// 'use strict';
var url = require('url');
var http = require('http');
var fs = require('fs');
var formidable = require("formidable");
var util = require('util');
var moment = require('moment');
var secureRandom = require('secure-random');
var jsonfile = require('jsonfile');
var cmd=require('node-cmd');

var crypto = require('crypto');
const commandLineArgs = require('command-line-args');

const optionDefinitions = [
    // option 'blockchain' set only when fabric blockchain network is contructed in docker
    { name: 'blockchain', alias: 'b', type: Boolean, defaultOption: false},
    { name: 'test', alias: 't', type: String }
]

const cmd_options = commandLineArgs(optionDefinitions);


var bodyParser = require('body-parser');
const winston = require('winston');
const tsFormat = () => (moment().format("YYYY-MM-DD HH:mm:ss"));
const logger = new (winston.Logger)({
  transports: [
    // colorize the output to the console
    new (winston.transports.Console)({
        timestamp: tsFormat,
        colorize: true 
    })
  ]
});

logger.level = 'debug';


var express = require("express");
var app = express();

var getScript = require("./default-script.js");
// console.log(getScript.script);
var appPort = 1185;

function start_server(app, port) {
    app.listen(port, function() {
        logger.info('Server is now listening on '+port);
    });
}

// Cross domain issue fixed. Referenced following link.
// http://stackoverflow.com/questions/28515351/xmlhttprequest-cannot-load-http-localhost3000-get
var allowCrossDomain = function(req, res, next) {
        // Website you wish to allow to connect
    res.setHeader('Access-Control-Allow-Origin', '*');

    // Request methods you wish to allow
    res.setHeader('Access-Control-Allow-Methods', 'GET, POST, OPTIONS, PUT, PATCH, DELETE');

    // Request headers you wish to allow
    res.setHeader('Access-Control-Allow-Headers', 'X-Requested-With,content-type');

    // Set to true if you need the website to include cookies in the requests sent
    // to the API (e.g. in case you use sessions)
    res.setHeader('Access-Control-Allow-Credentials', true);
   next();
}

app.use(allowCrossDomain);
app.use(bodyParser.urlencoded());

// Allow client to use /lib
app.use("/lib", express.static(__dirname + "/lib"));
app.use("/style", express.static(__dirname + "/style"));
app.use("/font-awesome-4.5.0", express.static(__dirname + "/templatemo_485_rainbow/font-awesome-4.5.0/"));
app.use("/css", express.static(__dirname + "/templatemo_485_rainbow/css/"));
app.use("/js", express.static(__dirname + "/templatemo_485_rainbow/js/"));
app.use("/img", express.static(__dirname + "/templatemo_485_rainbow/img/"));
app.use("/tabulator/*", express.static(__dirname + "/tabulator/*"));
app.use("/tabulator/dist/css/tabulator.min.css", express.static(__dirname + "/tabulator/dist/css/tabulator.min.css"));
app.use("/tabulator/dist/js/tabulator.min.js", express.static(__dirname + "/tabulator/dist/js/tabulator.min.js"));

app.get('/', function(req, res){
    response_client_html(res, "templatemo_485_rainbow/index.html");
});

app.get('/all', function(req, res) {
    displayForm(res);
});

app.get('/index.html', function(req, res) {
    response_client_html(res, "templatemo_485_rainbow/index.html");
});

app.get('/subscribe.html', function(req, res) {
    response_client_html(res, "subscribe.html");
});

app.get('/open-lottery.html', function(req, res) {
    response_client_html(res, "open-lottery.html");
});

app.post('/subscribe', function(req, res) {
    logger.info("/subscribe")
});


app.post('/register-lottery', function(req, res) {
    processAllFieldsOfTheForm(req, res);
});

// check the result( = check the winner(s))
app.post('/check', function(req, res) {
    logger.info("/check")
});

app.post('/verify', function(req, res) {
    logger.info("/verify requested");
});

app.post('/cc-query-all-events', function(req, res) {
    logger.info("/cc-query-all-events requested")
});

function response_client_html(res, filename) {
    fs.readFile(filename, function (err, data) {
        res.writeHead(200, {
            'Content-Type': 'text/html',
        });
        res.write(data);
        res.end();
    });
    logger.info(filename + " requested");
}

// client enrollment request
app.post('/enrollment', function(req, res) {
    logger.info("/enrollment Requested");
});

app.post('/register-identity', function(req, res) {
    logger.info("/register-identity Requested");
});

app.post('/create-channel', function(req, res) {
    logger.info("/created-channel Requested");
});

app.post('/join-channel', function(req, res) {
    logger.info("/join-channel Requested");
});

app.post('/install-chaincode', function(req, res) {
    logger.info("/install-chaincode Requested");
});

app.post('/instantiate-chaincode', function(req, res) {
    logger.info("/instantiate_chaincode Requested");
});

app.post('/invoke-chaincode', function(req, res) {
    logger.info("/invoke-chaincode Requested");

});

app.post('/query-chaincode', function(req, res) {
    logger.info("/query-chaincode Requested");

    logger.info("response_payloads type: " + typeof response_payloads);


});

app.post('/register-user', function(req, res) {
    logger.info("/register-user Requested");

    res.writeHead(200, {
        'content-type' : 'text/plain'
    });
    res.write("hi");
    res.end();
    
});

var func_numargs_map = new Object();
// including function name itself
func_numargs_map["create_lottery_event"] = 7;
func_numargs_map["query_lottery_event"] = 2;
func_numargs_map["create_target_block"] = 2;
func_numargs_map["query_target_block"] = 2;
func_numargs_map["determine_winner"] = 2;
func_numargs_map["query_winner"] = 2;
func_numargs_map["query_all_lottery"] = 2;

var FunctionType = new Object();
FunctionType["create_lottery_event"] = "invoke";
FunctionType["query_lottery_event"] = "query";
FunctionType["create_target_block"] = "invoke";
FunctionType["query_target_block"] = "query";
FunctionType["determine_winner"] = "invoke";
FunctionType["query_winner"] = "query";
FunctionType["query_all_lottery"] = "query";
const MAX_CC_ARGS = 7;

// References https://nehakadam.github.io/DateTimePicker/
function datetimeToTimestamp(datetime) {
    var timestamp;
    var tmpdt = new Date(datetime);
    timestamp = tmpdt.getTime();
    return timestamp / 1000;
}

app.post('/admin-register', function(req, res) {
    logger.info("/admin-register Requested");
})

function process_invoke_args(req) {
    var obj = req.body;
    // console.log(req.body);
    var function_name = obj.arg0;
    var args = [];
    var numargs = func_numargs_map[function_name];
    var f_type = FunctionType[function_name];
    var invoke_info = {};

    args[0] = obj.arg0;
    args[1] = obj.arg1;
    args[2] = obj.arg2;
    args[3] = obj.arg3;
    args[4] = obj.arg4;
    args[5] = obj.arg5;
    args[6] = obj.arg6;

    for (var i = 0; i < MAX_CC_ARGS - numargs; ++i) {
        args.pop();
    }

    /* console.log(function_name);
    console.log(args);  */
    invoke_info = {
        "args" : args,
        "f_type" : f_type,
    };
    return invoke_info;
}

function displayForm(res) {
    fs.readFile('form.html', function (err, data) {
        res.writeHead(200, {
            'Content-Type': 'text/html',
                'Content-Length': data.length
        });
        res.write(data);
        res.end();
    });
}

// cryptographic random generator
// https://www.npmjs.com/package/secure-random
function get_cryptosecure_num() {

    var randomarray = secureRandom.randomUint8Array(10)
    console.log("Your lucky numbers:");
    var str = "";
    for (var i = 0; i < randomarray.length; i++) {
        console.log(randomarray[i]);
        str += randomarray[i].toString(16);
    }
    console.log(str);
    return str;
}

// get_cryptosecure_num();
function processAllFieldsOfTheForm(req, res) {
    var eventName;
    var datetime; // due date
    var issuedate;
    var announcementdate;
    var futureblock;
    var numOfMembers;
    var numOfWinners;
    var memberList; 
    var randomKey;
    var ManifestHash;
    var args = [];

    var form = new formidable.IncomingForm();
    form.parse(req, function (err, fields, files) {

        ManifestHash = fields.ManifestHash;
        eventName = fields.EventName;
        datetime = fields.DateTime;
        issuedate = fields.IssueDate;
        announcementdate = fields.AnnouncementDate;
        futureblock = fields.fblock;
        numOfMembers = fields.numOfMembers;
        numOfWinners = fields.numOfWinners;
        randomKey = fields.RandomKey;
        memberList = fields.MemberList;

        console.log(eventName);
        console.log(datetime, datetimeToTimestamp(datetime), typeof datetimeToTimestamp(datetime));
        console.log(issuedate, datetimeToTimestamp(issuedate),typeof datetimeToTimestamp(datetime));
        console.log(announcementdate, datetimeToTimestamp(announcementdate),typeof datetimeToTimestamp(datetime));
        console.log(futureblock);
        console.log(numOfMembers);
        console.log(numOfWinners);
        console.log(randomKey);
        console.log(memberList);
        console.log(ManifestHash);

        // format argument array to be input for chaincode
        args[0] = "create_lottery_event_hash"; // function name of chaincode
        args[1] = ManifestHash;
        args[2] = eventName;
        args[3] = datetimeToTimestamp(issuedate).toString();
        args[4] = datetimeToTimestamp(datetime).toString();
        args[5] = datetimeToTimestamp(announcementdate).toString();
        args[6] = futureblock;
        args[7] = numOfMembers;
        args[8] = numOfWinners;
        args[9] = randomKey;
        // args[9] = memberList;
        args[10] = getScript.script;

        var obj = {
            "ManifestHash" : ManifestHash,
            "EventName" : eventName,
            "IssueDate" : issuedate,
            "DueDateTime" : datetime,
            "AnnouncementDate" : announcementdate,
            "FutureTargetBlock": futureblock,
            "numOfMembers": numOfMembers,
            "numOfWinners": numOfWinners,
            "RandomKey": randomKey,
            // "MemberList": memberList,
            "script": getScript.script,
        }

        console.log(obj);
        var fname = "inputmanifests/" + "lottery-" + ManifestHash + ".json";

        jsonfile.writeFileSync(fname, obj, {spaces:2}, function(err) {
            console.log(err);
        });

        var text = "Manifest " + ManifestHash
        + "<br>\{ <br> &nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;\"EventName\":&nbsp;" + eventName
        + ",<br> &nbsp;&nbsp;&nbsp;&nbsp;&nbsp; \"Status\":&nbsp;" + "1"
        + ",<br> &nbsp;&nbsp;&nbsp;&nbsp;&nbsp; \"IssueDate\":&nbsp;" + issuedate
        + ",<br> &nbsp;&nbsp;&nbsp;&nbsp;&nbsp; \"DueDate\":&nbsp;" + datetime
        + ",<br> &nbsp;&nbsp;&nbsp;&nbsp;&nbsp; \"AnnouncementDate\":&nbsp;" + announcementdate
        + ",<br> &nbsp;&nbsp;&nbsp;&nbsp;&nbsp; \"FutureBlock\":&nbsp;" + futureblock
        + ",<br> &nbsp;&nbsp;&nbsp;&nbsp;&nbsp; \"numOfMembers\":&nbsp;" + numOfMembers
        + ",<br> &nbsp;&nbsp;&nbsp;&nbsp;&nbsp; \"numOfWinners\":&nbsp;"+  numOfWinners
        + ",<br> &nbsp;&nbsp;&nbsp;&nbsp;&nbsp; \"randomKey\":&nbsp;" + randomKey
        + ",<br> &nbsp;&nbsp;&nbsp;&nbsp;&nbsp; \"MemberList\":&nbsp;" + memberList
        + ",<br> &nbsp;&nbsp;&nbsp;&nbsp;&nbsp; \"WinnerList\":&nbsp;" + "UNDEFINED"
        + ",<br> &nbsp;&nbsp;&nbsp;&nbsp;&nbsp; \"script\": " + getScript.script
        + "<br>"
        + "\}"

        var downtexts = [
            '<a href="/inputmanifests/lottery-"'
        ];
        res.writeHead(200, {
            'content-type' : 'text/html'
        });
        res.write('<b>Event is being processed in blokchain network. Wait a few seconds</b><br><br>');

        setTimeout(function() {
            LotteryChainInterface.invoke_chaincode(args).then(function() {
                res.write(
                    '<a href="/open-lottery.html"' + '>prev</a><br>'
                    + '<b>Lottery Manifest<br>Congratuation! You just registered lottery event successfully. Lottery event is stored in blockchain network built upon hyperledger/fabric.</b>'
                    + "<b>You can download manifest file and use it later to check result</b><br>"
                    + "<b>This manifest file is temporary. It will be change over time whenever new members joined</b><br>"
                    + '<a download href="/inputmanifests/lottery-' + ManifestHash + '.json"'  + '>download manifest</a>'
                    + '<br><br>'
                    + text
                    + "<br>"
                    + "<br>"
                );
                    
            })
        }, 500);
            
    });

    /* res.end(util.inspect({
            fields: fields,
            files: files
        })); */
}

start_server(app, appPort);
// setTimeout(e2e_test, 500);

if (cmd_options.blockchain) {
    // well working function
    console.log("e2e_test start");
    setTimeout(e2e_test, 2000);
} else {

} 


