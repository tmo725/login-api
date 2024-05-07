var express = require("express");
var app = express();
const dotenv = require('dotenv');
dotenv.config();
const {OAuth2Client} = require('google-auth-library');

app.use(cors());

app.post('/', async function(req, res, next) {
    res.header('Access-Control-Allow-Origin', 'http://localhost:3001/');
    res.header('Referrer-Policy','no-referrer-when-downgrade');

    const redirectUrl = 'http://127.0.0.1:3000/oauth';
    const oAuth2Client = new OAuth2Client(
        process.env.CLIENT_ID,
        process.env.CLIENT_SECRET,
        redirectUrl
    );

    const authorizeUrl = oAuth2Client.generateAuthUrl({
        access_type:'offline',
        scope:'https://www.googleapis.com/auth/userinfo.profile openid',
        promt:'consent'
    });

    res.json({url:authorizeUrl})
});

app.listen(3000, jsonParser, function () {
    console.log("CORS-enabled web server listening on port 3333");
  });