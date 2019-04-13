const express = require("express");
const helmet = require("helmet");
const cors = require("cors");
const bcrypt = require("bcryptjs");

const db = require("./database/dbConfig.js");
const Users = require("./users/users-model.js");

const server = express();

server.use(helmet());
server.use(express.json());
server.use(cors());

server.get("/", (req, res) => {
  res.send("It's alive!");
});

server.post("/api/register", (req, res) => {
  let user = req.body;
  //hash password
  user.password = bcrypt.hashSync(user.password, 10);

  Users.add(user)
    .then(saved => {
      res.status(201).json(saved);
    })
    .catch(error => {
      res.status(500).json(error);
    });
});

server.post("/api/login", (req, res) => {
  let { username, password } = req.body;

  Users.findBy({ username })
    .first()
    .then(user => {
      // check password against database
      if (user && bcrypt.compareSync(password, user.password)) {
        res.status(200).json({ message: `Welcome ${user.username}!` });
      } else {
        res.status(401).json({ message: "Invalid Credentials" });
      }
    })
    .catch(error => {
      res.status(500).json(error);
    });
});

//restrict access only if right credentials are in header
server.get("/api/users", restricted, only("theuser1"), (req, res) => {
  Users.find()
    .then(users => {
      res.json(users);
    })
    .catch(err => res.send(err));
});

function restricted(req, res, next) {
  const { username, password } = req.headers;

  if ((username, password)) {
    Users.findBy({ username })
      .first()
      .then(user => {
        if (user && bcrypt.compareSync(password, user.password)) {
          next();
        } else {
          res.status(401).json({ message: "Invalid Credentials" });
        }
      })
      .catch(error => {
        res.status(500).json(error);
      });
  } else {
    res.status(401).json({ message: "Missing credentials." });
  }
}

// function only(req, res, next) {
//   const { username } = req.headers;
//   if (username != "theuser1") {
//     res
//       .status(403)
//       .json({ message: "You do not have access to this information." });
//   } else {
//     next();
//   }
// }

function only(username) {
  return function(req, res, next) {
    if (req.headers.username) {
      if (req.headers.username === username) {
        next();
      } else {
        res
          .status(403)
          .json({ message: "You are not authorized to access this." });
      }
    } else {
      res.status(400).json({ message: "No username provided." });
    }
  };
}

const port = process.env.PORT || 5000;
server.listen(port, () => console.log(`\n** Running on port ${port} **\n`));
