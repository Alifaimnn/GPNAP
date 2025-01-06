// Choose map - Authenticated route
app.post('/choose-map', verifyToken, (req, res) => {
  const selectedMapName = req.body.selectedMap;

  function mapJsonPathExists(mapPath) {
    try {
      fs.accessSync(mapPath, fs.constants.F_OK);
      return true;
    } catch (err) {
      return false;
    }
  }

  const mapJsonPath = path.join(__dirname, ${selectedMapName}.json);

  if (mapJsonPathExists(mapJsonPath)) {
    const mapData = JSON.parse(fs.readFileSync(mapJsonPath, 'utf-8'));
    req.identity.selectedMap = selectedMapName; // Store the selected map in the JWT
    req.identity.playerPosition = mapData.playerLoc; // Set initial player position
    const room1Message = mapData.map.room1.message;

    res.send(You choose ${selectedMapName}. Let's start playing!\n\nRoom 1 Message:\n${room1Message});
  } else {
    res.status(404).send(Map "${selectedMapName}" not found.);
  }
});
// Move - Authenticated route
app.patch('/move', verfiytoken(req, res) => {
  const direction = req.body.direction;

  if (!req.identity.selectedMap) {
    return res.status(400).send("No map selected.");
  }
  const selectedMapName = req.identity.selectedMap;
  const mapData = require(./${selectedMapName}.json);
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