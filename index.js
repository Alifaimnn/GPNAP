const express = require('express')
const app = express()
const port = process.env.PORT || 4000;
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');



app.use(express.json())


//user registration
app.post('/user', async (req,res) => {
  //check if username already exist
  //insertOne registration data to mongo
  const hash = bcrypt.hashSync(req.body.password, 15);

  let result = await client.db("user").collection("userdetail").insertOne(
    {
      username : req.body.username,
      password : hash,
      name : req.body.name,
      email : req.body.email
    }
  )
  res.send(result)
})

//user login 
app.post('/login', async (req,res) => {
  // step #1: req.body.username ??
  if (req.body.username != null && req.body.password != null) {
    let result = await client.db("user").collection("userdetail").findOne({
      username: req.body.username
    })

    if (result) {
      // step #2: if user exist, check if password is correct
      if (bcrypt.compareSync(req.body.password, result.password) == true) {
        // password is correct
        var token = jwt.sign(
          { _id: result._id, username: result.username, name: result.name },
          'hurufasepuluhkali'
        );
        res.send(token)
      } else {
        // password is incorrect
        res.status(401).send('WRONG PASSWORD! TRY AGAIN')
      }

    } else {
      // step #3: if user not found
      res.status(401).send("USERNAME NOT FOUND")
    }
  } else {
    res.status(400).send("MISSING USERNAME OR PASSWORD")
  }
})


// get user profile
app.get('/user/:id', verifyToken, async (req, res) => {
  
  if (req.identity._id != req.params.id) {
    res.status(401).send('Unauthorized Access')
  } else {
    let result = await client.db("user").collection("userdetail").findOne({
      _id: new ObjectId(req.params.id)
    })
    res.send(result)
  }
})



// update user account
app.patch('/user/:id', verifyToken, async (req, res) => {
  if (req.identity._id != req.params.id) {
    res.send('Unauthorized')
  } else {
    let result = await client.db("user").collection("userdetail").updateOne(
      {
        _id: new ObjectId(req.params.id)
      },
      {
        $set: {
          name: req.body.name
        }
      }
    )
    res.send(result)
  }
})

// delete user account
app.delete('/user/:id', verifyToken, async (req, res) => {
  let result = await client.db("user").collection("userdetail").deleteOne(
    {
      _id: new ObjectId(req.params.id)
    }
  )
  res.send(result);
});

app.post('/buy', async (req, res) => {
  const token = req.headers.authorization.split(" ")[1]

  var decoded = jwt.verify(token, 'mysupersecretpasskey');
  console.log(decoded)
})



app.post('/choose-map', (req,res) => {
  

  const selectedMap = req.body.selectedMap;
  console.log(req.identity)
  
  const fs = require('fs');

  function mapJsonPathExists(mapPath) {
    try {
      // Check if the file exists synchronously
      fs.accessSync(mapPath, fs.constants.F_OK);
      return true; // File exists
    } catch (err) {
      return false; // File does not exist
  }
}
  //construct path to html file based on map name
  const mapJsonpath = `./${selectedMap}.json`;
  

  //check if map is exist or not
  if (mapJsonPathExists(mapJsonpath)) {

    const mapData = require(mapJsonpath);
  
    const room1Message = mapData.map.room1.message;

    res.send(`You choose ${selectedMap}.Lets start Play!\n\nRoom 1 Message:\n${room1Message}`);

  
  } else {
    res.status(404).send(`Map "${selectedMap}" not found.`);
  }
});


app.listen(port, () => {
   console.log(`Example app listening on port ${port}`)
})


const { MongoClient, ServerApiVersion } = require('mongodb');
const uri = "mongodb+srv://7naa:hurufasepuluhkali@cluster0.4oeznz2.mongodb.net/?retryWrites=true&w=majority&appName=Cluster0";

// Create a MongoClient with a MongoClientOptions object to set the Stable API version
const client = new MongoClient(uri, {
  serverApi: {
    version: ServerApiVersion.v1,
    strict: true,
    deprecationErrors: true,
  }
})

function verifyToken(req, res, next) {
  const authHeader = req.headers.authorization
  const token = authHeader && authHeader.split(' ')[1]

  if (token == null) return res.sendStatus(401)

  jwt.verify(token, "hurufasepuluhkali", (err, decoded) => {
    console.log(err)

    if (err) return res.sendStatus(403)

    req.identity = decoded

    next()
  })
}

async function run() {
  try {
    // Connect the client to the server	(optional starting in v4.7)
    await client.connect();
    // Send a ping to confirm a successful connection
    await client.db("admin").command({ ping: 1 });
    console.log("Pinged your deployment. You successfully connected to MongoDB!");
  } finally {
    // Ensures that the client will close when you finish/error
    //await client.close();
  }
}
run().catch(console.dir);
