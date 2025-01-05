const express = require('express');
const app = express();
const port = process.env.PORT || 4000;
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const { MongoClient, ServerApiVersion, ObjectId } = require('mongodb');

// Middleware to parse JSON in request body
app.use(express.json());

const uri = "mongodb+srv://7naa:hurufasepuluhkali@cluster0.4oeznz2.mongodb.net/?retryWrites=true&w=majority&appName=Cluster0";
const client = new MongoClient(uri, {
  serverApi: {
    version: ServerApiVersion.v1,
    strict: true,
    deprecationErrors: true,
  },
});

// Middleware to verify JWT token
function verifyToken(req, res, next) {
  const authHeader = req.headers.authorization;
  const token = authHeader && authHeader.split(' ')[1];

  if (token == null) return res.sendStatus(401);

  jwt.verify(token, "hurufasepuluhkali", (err, decoded) => {
    if (err) return res.sendStatus(403);
    req.identity = decoded;
    next();
  });
}

// Middleware to verify admin
function verifyAdmin(req, res, next) {
  if (!req.identity || !req.identity.isAdmin) {
    return res.status(403).send("Access denied. Admins only.");
  }
  next();
}

// User registration for regular users
app.post('/register', async (req, res) => {
  try {
    const { username, password, name, email } = req.body;

    if (!username || !password || !name || !email) {
      return res.status(400).send("All fields are required.");
    }

    const existingUser = await client.db("user").collection("userdetail").findOne({ username });
    if (existingUser) {
      return res.status(400).send("Username already exists. Please choose a different username.");
    }

    if (password.length < 8) {
      return res.status(400).send("Password must be at least 8 characters long.");
    }

    const hash = bcrypt.hashSync(password, 15);

    await client.db("user").collection("userdetail").insertOne({
      username,
      password: hash,
      name,
      email,
      isAdmin: false, // Regular users cannot be admin
    });

    res.status(201).send("User registered successfully.");
  } catch (error) {
    console.error("Error during registration:", error);
    res.status(500).send("Internal server error.");
  }
});

// Admin registration (only admins can create new admins)
app.post('/user', verifyToken, verifyAdmin, async (req, res) => {
  try {
    const { username, password, name, email, isAdmin } = req.body;

    if (!username || !password || !name || !email) {
      return res.status(400).send("All fields are required.");
    }

    const existingUser = await client.db("user").collection("userdetail").findOne({ username });
    if (existingUser) {
      return res.status(400).send("Username already exists. Please choose a different username.");
    }

    if (password.length < 8) {
      return res.status(400).send("Password must be at least 8 characters long.");
    }

    const hash = bcrypt.hashSync(password, 15);

    await client.db("user").collection("userdetail").insertOne({
      username,
      password: hash,
      name,
      email,
      isAdmin: isAdmin || false, // If isAdmin is provided, use it; otherwise, default to false
    });

    res.status(201).send("User registered successfully.");
  } catch (error) {
    console.error("Error during registration:", error);
    res.status(500).send("Internal server error.");
  }
});

// Admin can view all users
app.get('/users', verifyToken, verifyAdmin, async (req, res) => {
  try {
    const users = await client.db("user").collection("userdetail").find().toArray();
    res.status(200).send(users);
  } catch (error) {
    console.error("Error fetching users:", error);
    res.status(500).send("Internal server error.");
  }
});

// Admin can delete a user
app.delete('/user/:id', verifyToken, verifyAdmin, async (req, res) => {
  try {
    const { id } = req.params;

    // Check if the user exists
    const user = await client.db("user").collection("userdetail").findOne({ _id: new ObjectId(id) });
    if (!user) {
      return res.status(404).send("User not found.");
    }

    // Delete the user
    await client.db("user").collection("userdetail").deleteOne({ _id: new ObjectId(id) });

    res.status(200).send("User deleted successfully.");
  } catch (error) {
    console.error("Error deleting user:", error);
    res.status(500).send("Internal server error.");
  }
});

// Admin can view their own profile
app.get('/admin/profile', verifyToken, verifyAdmin, async (req, res) => {
  try {
    const adminId = req.identity._id;

    const admin = await client.db("user").collection("userdetail").findOne({ _id: new ObjectId(adminId) });

    if (!admin) {
      return res.status(404).send("Admin not found.");
    }

    res.status(200).send({
      _id: admin._id,
      username: admin.username,
      name: admin.name,
      email: admin.email,
      isAdmin: admin.isAdmin,
    });
  } catch (error) {
    console.error("Error fetching admin profile:", error);
    res.status(500).send("Internal server error.");
  }
});

// Admin can update their own profile
app.patch('/admin/profile', verifyToken, verifyAdmin, async (req, res) => {
  try {
    const { name, email } = req.body;
    const adminId = req.identity._id;

    if (!name && !email) {
      return res.status(400).send("At least one field (name or email) is required to update.");
    }

    const updateFields = {};
    if (name) updateFields.name = name;
    if (email) updateFields.email = email;

    // Update the admin's profile
    await client.db("user").collection("userdetail").updateOne(
      { _id: new ObjectId(adminId) },
      { $set: updateFields }
    );

    res.status(200).send("Admin profile updated successfully.");
  } catch (error) {
    console.error("Error updating admin profile:", error);
    res.status(500).send("Internal server error.");
  }
});

// User login
app.post('/login', async (req, res) => {
  try {
    const { username, password } = req.body;

    if (!username || !password) {
      return res.status(400).send("Missing username or password.");
    }

    const user = await client.db("user").collection("userdetail").findOne({ username });

    if (!user) {
      return res.status(401).send("Username not found.");
    }

    const passwordMatch = bcrypt.compareSync(password, user.password);

    if (!passwordMatch) {
      return res.status(401).send("Wrong password! Try again.");
    }

    const token = jwt.sign(
      { _id: user._id, username: user.username, name: user.name, isAdmin: user.isAdmin },
      'hurufasepuluhkali'
    );

    if (user.isAdmin) {
      return res.status(200).send({
        message: `Welcome admin ${user.username}`,
        _id: user._id.toString(),
        token: token,
      });
    } else {
      return res.status(200).send({
        _id: user._id.toString(),
        token: token,
      });
    }
  } catch (error) {
    console.error("Error during login:", error);
    res.status(500).send("Internal server error.");
  }
});

// Get user profile
app.get('/profile', verifyToken, async (req, res) => {
  try {
    const userId = req.identity._id;

    const user = await client.db("user").collection("userdetail").findOne({ _id: new ObjectId(userId) });

    if (!user) {
      return res.status(404).send("User not found.");
    }

    res.status(200).send({
      _id: user._id,
      username: user.username,
      name: user.name,
      email: user.email,
      selectedMap: user.selectedMap,
      playerPosition: user.playerPosition,
    });
  } catch (error) {
    console.error("Error fetching profile:", error);
    res.status(500).send("Internal server error.");
  }
});

// Update user profile
app.patch('/profile', verifyToken, async (req, res) => {
  try {
    const { name, email } = req.body;
    const userId = req.identity._id;

    if (!name && !email) {
      return res.status(400).send("At least one field (name or email) is required to update.");
    }

    const updateFields = {};
    if (name) updateFields.name = name;
    if (email) updateFields.email = email;

    await client.db("user").collection("userdetail").updateOne(
      { _id: new ObjectId(userId) },
      { $set: updateFields }
    );

    res.status(200).send("Profile updated successfully.");
  } catch (error) {
    console.error("Error during profile update:", error);
    res.status(500).send("Internal server error.");
  }
});

// Set map and player position
app.post('/select-map', verifyToken, async (req, res) => {
  try {
    const { mapId } = req.body;
    const userId = req.identity._id;

    if (!mapId) {
      return res.status(400).send("Map ID is required.");
    }

    await client.db("user").collection("userdetail").updateOne(
      { _id: new ObjectId(userId) },
      { $set: { selectedMap: mapId } }
    );

    res.status(200).send("Map selected successfully.");
  } catch (error) {
    console.error("Error during map selection:", error);
    res.status(500).send("Internal server error.");
  }
});

// Move player in a specific direction
app.post('/move', verifyToken, async (req, res) => {
  try {
    const { direction } = req.body;
    const userId = req.identity._id;

    if (!direction || !["up", "down", "left", "right"].includes(direction)) {
      return res.status(400).send("Invalid direction. Please choose 'up', 'down', 'left', or 'right'.");
    }

    let newPosition;
    switch (direction) {
      case 'up':
        newPosition = { x: 0, y: 1 };
        break;
      case 'down':
        newPosition = { x: 0, y: -1 };
        break;
      case 'left':
        newPosition = { x: -1, y: 0 };
        break;
      case 'right':
        newPosition = { x: 1, y: 0 };
        break;
      default:
        return res.status(400).send("Invalid direction.");
    }

    await client.db("user").collection("userdetail").updateOne(
      { _id: new ObjectId(userId) },
      { $set: { playerPosition: newPosition } }
    );

    res.status(200).send(`Player moved ${direction}.`);
  } catch (error) {
    console.error("Error during move:", error);
    res.status(500).send("Internal server error.");
  }
});

// Start server
app.listen(port, () => {
  console.log(`Example app listening on port ${port}`);
});

// Connect to MongoDB
async function run() {
  try {
    await client.connect();
    await client.db("admin").command({ ping: 1 });
    console.log("Pinged your deployment. You successfully connected to MongoDB!");
  } finally {}
}
run().catch(console.dir);
