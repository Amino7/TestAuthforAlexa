//npm modules
const express = require('express');
const http = require('http');

// create the server
const app = express();

app.get('/alexa',(req,res) =>{
  res.send('kommt noch...');
  console.log("alexa hat auf mich zugegriffen!")
})



// tell the server what port to listen on
http.createServer( app).listen(process.env.PORT,"0.0.0.0");
console.log('Listening on localhost:8080')

//TODO: test module safety with nsp&snyk
