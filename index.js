const express = require('express');
const app = express();
const port = process.env.PORT || 4000;
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const fs = require('fs');
const { MongoClient, ServerApiVersion, ObjectId } = require('mongodb');

// Middleware to parse JSON in request body
app.use(express.json());

const uri = "mongodb+srv://7naa:hurufasepuluhkali@cluster0.4oeznz2.mongodb.net/?retryWrites=true&w=majority&appName=Cluster0";
const client = new MongoClient(uri, {
  serverApi: {
    version: ServerApiVersion.v1,
    strict: true,
    deprecationErrors: true,
  }
});

let selectedMap = null;
let playerPosition = null;

// Function to verify JWT token
function verifyToken(req, res, next) {
  const authHeader = req.headers.authorization;
  const token = authHeader && authHeader.split(' ')[1];

  if (token == null) return res.sendStatus(401);

  jwt.verify(token, "hurufasepuluhkali", (err, decoded) => {
    console.log(err);

    if (err) return res.sendStatus(403);

    req.identity = decoded;

    next();
  });
}

// User registration
app.post('/user', async (req, res) => {
  const hash = bcrypt.hashSync(req.body.password, 15);

  let result = await client.db("user").collection("userdetail").insertOne({
    username: req.body.username,
    password: hash,
    name: req.body.name,
    email: req.body.email
  });
  res.send(result);
});

// User login
app.post('/login', async (req, res) => {
  if (req.body.username != null && req.body.password != null) {
    let result = await client.db("user").collection("userdetail").findOne({
      username: req.body.username
    });

    if (result) {
      if (bcrypt.compareSync(req.body.password, result.password) == true) {
        var token = jwt.sign(
          { _id: result._id, username: result.username, name: result.name },
          'hurufasepuluhkali'
        );
        res.send(token);
      } else {
        res.status(401).send('WRONG PASSWORD! TRY AGAIN');
      }
    } else {
      res.status(401).send("USERNAME NOT FOUND");
    }
  } else {
    res.status(400).send("MISSING USERNAME OR PASSWORD");
  }
});

// Get user profile
app.get('/user/:id', verifyToken, async (req, res) => {
  if (req.identity._id != req.params.id) {
    res.status(401).send('Unauthorized Access');
  } else {
    let result = await client.db("user").collection("userdetail").findOne({
      _id: new ObjectId(req.params.id)
    });
    res.send(result);
  }
});

// Update user account
app.patch('/user/:id', verifyToken, async (req, res) => {
  if (req.identity._id != req.params.id) {
    res.send('Unauthorized');
  } else {
    let result = await client.db("user").collection("userdetail").updateOne({
      _id: new ObjectId(req.params.id)
    }, {
      $set: {
        name: req.body.name
      }
    });
    res.send(result);
  }
});

// Delete user account
app.delete('/user/:id', verifyToken, async (req, res) => {
  let result = await client.db("user").collection("userdetail").deleteOne({
    _id: new ObjectId(req.params.id)
  });
  res.send(result);
});

app.post('/buy', async (req, res) => {
  const token = req.headers.authorization.split(" ")[1];
  var decoded = jwt.verify(token, 'mysupersecretpasskey');
  console.log(decoded);
});

app.post('/choose-map', (req, res) => {
  const selectedMapName = req.body.selectedMap;

  function mapJsonPathExists(mapPath) {
    try {
      fs.accessSync(mapPath, fs.constants.F_OK);
      return true;
    } catch (err) {
      return false;
    }
  }

  const mapJsonPath = ./${selectedMapName}.json;

  if (mapJsonPathExists(mapJsonPath)) {
    const mapData = require(mapJsonPath);
    selectedMap = selectedMapName; // Store the selected map globally
    playerPosition = mapData.playerLoc; // Set initial player position
    const room1Message = mapData.map.room1.message;

    res.send(You choose ${selectedMapName}. Let's start playing!\n\nRoom 1 Message:\n${room1Message});
  } else {
    res.status(404).send(Map "${selectedMapName}" not found.);
  }
});

app.patch('/move', (req, res) => {
  const direction = req.body.direction;

  if (!selectedMap) {
    res.status(400).send("No map selected.");
    return;
  }

  const mapData = require(./${selectedMap}.json);
  const currentRoom = mapData.map[playerPosition];

  const nextRoom = currentRoom[direction];
  if (!nextRoom) {
    res.status(400).send(Invalid direction: ${direction});
    return;
  }

  const nextRoomMessage = mapData.map[nextRoom].message;
  playerPosition = nextRoom;

  res.send(You moved ${direction}. ${nextRoomMessage});
});

app.listen(port, () => {
  console.log(Example app listening on port ${port});
});

async function run() {
  try {
    await client.connect();
    await client.db("admin").command({ ping: 1 });
    console.log("Pinged your deployment. You successfully connected to MongoDB!");
  } finally {
    // Ensures that the client will close when you finish/error
    // await client.close();
  }
}
run().catch(console.dir);