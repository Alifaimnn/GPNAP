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
    if (err) return res.sendStatus(403);

    req.identity = decoded; // Attach decoded user data to the request
    next();
  });
}

// Middleware to verify admin role
function verifyAdmin(req, res, next) {
  const authHeader = req.headers.authorization;
  const token = authHeader && authHeader.split(' ')[1];

  if (!token) return res.status(401).send('Unauthorized: Token is required.');

  jwt.verify(token, "hurufasepuluhkali", (err, decoded) => {
    if (err) return res.status(403).send('Forbidden: Invalid token.');
    if (decoded.role !== "admin") return res.status(403).send("Forbidden: Admins only.");

    req.identity = decoded; // Attach decoded admin data to the request
    next();
  });
}

// Admin login
app.post('/admin/login', async (req, res) => {
  const { username, password } = req.body;

  if (username && password) {
    let admin = await client.db("admin").collection("admindetail").findOne({ username });

    if (admin) {
      if (bcrypt.compareSync(password, admin.password)) {
        const token = jwt.sign(
          { _id: admin._id, username: admin.username, role: "admin" },
          'hurufasepuluhkali'
        );
        res.send({ _id: admin._id, token, role: "admin" }); // Send _id, token, and role
      } else {
        res.status(401).send('Wrong password! Try again');
      }
    } else {
      res.status(401).send("Admin username not found");
    }
  } else {
    res.status(400).send("Missing admin username or password");
  }
});

// User registration
app.post('/user', async (req, res) => {
  const { username, password, name, email } = req.body;

  // Password requirement: Minimum 8 characters
  if (password.length < 8) {
    return res.status(400).send("Password must be at least 8 characters long.");
  }

  // Check for duplicate username
  const existingUser = await client.db("user").collection("userdetail").findOne({ username });
  if (existingUser) {
    return res.status(400).send("Username already exists.");
  }

  const hash = bcrypt.hashSync(password, 15);

  let result = await client.db("user").collection("userdetail").insertOne({
    username,
    password: hash,
    name,
    email
  });
  res.send(result);
});

// User login
app.post('/login', async (req, res) => {
  const { username, password } = req.body;

  if (username && password) {
    let result = await client.db("user").collection("userdetail").findOne({ username });

    if (result) {
      if (bcrypt.compareSync(password, result.password)) {
        const token = jwt.sign(
          { _id: result._id, username: result.username, name: result.name, role: "user" },
          'hurufasepuluhkali'
        );
        res.send({ _id: result._id, token, role: "user" }); // Send _id, token, and role
      } else {
        res.status(401).send('Wrong password! Try again');
      }
    } else {
      res.status(401).send("Username not found");
    }
  } else {
    res.status(400).send("Missing username or password");
  }
});

// Example admin-only route
app.get('/admin/dashboard', verifyAdmin, async (req, res) => {
  try {
    const users = await client.db("user").collection("userdetail").find({}).toArray();
    res.send(users);
  } catch (err) {
    console.error(err);
    res.status(500).send('Server error');
  }
});

// Get user profile
app.get('/user/:id', verifyToken, async (req, res) => {
  if (req.identity._id != req.params.id) {
    return res.status(401).send('Unauthorized access');
  }

  let result = await client.db("user").collection("userdetail").findOne({
    _id: new ObjectId(req.params.id)
  });
  res.send(result);
});

// Update user profile - Authenticated route
app.patch('/user/:id', verifyToken, async (req, res) => {
  if (req.identity._id != req.params.id) {
    return res.status(401).send('Unauthorized access');
  }

  const { name, email, password } = req.body;

  const updateData = {};

  if (name) {
    updateData.name = name;
  }

  if (email) {
    const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    if (!emailRegex.test(email)) {
      return res.status(400).send("Invalid email format.");
    }

    const emailExists = await client.db("user").collection("userdetail").findOne({ email });
    if (emailExists && emailExists._id.toString() !== req.params.id) {
      return res.status(400).send("Email is already in use by another account.");
    }
    updateData.email = email;
  }

  if (password) {
    if (password.length < 8) {
      return res.status(400).send("Password must be at least 8 characters long.");
    }

    updateData.password = bcrypt.hashSync(password, 15);
  }

  try {
    let result = await client.db("user").collection("userdetail").updateOne(
      { _id: new ObjectId(req.params.id) },
      { $set: updateData }
    );

    if (result.modifiedCount > 0) {
      res.send('Profile updated successfully');
    } else {
      res.status(400).send('No changes made to the profile');
    }
  } catch (err) {
    console.error(err);
    res.status(500).send('Server error');
  }
});

// Start the server
app.listen(port, () => {
  console.log(`Server running on port ${port}`);
});

// MongoDB connection setup
async function run() {
  try {
    await client.connect();
    console.log('Connected to MongoDB successfully!');
  } catch (error) {
    console.error('Failed to connect to MongoDB:', error);
  }
}
run().catch(console.dir); 