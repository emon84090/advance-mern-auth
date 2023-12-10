const express = require("express");
const cors = require("cors");
const app = express();
const PORT = 5000;
const dbCOnnect = require("./utils/dbconnection");
const authroute = require("./route/auth.route");
const xss = require("xss-clean");

app.use(cors());
app.use(express.json());
app.use(xss());

dbCOnnect();

app.get("/", (req, res) => {
  res.status(200).send("Blood Donaition Server is Running");
});

app.use("/api/auth", authroute);

app.use((err, req, res, next) => {
  const status = err.statusCode || 500;
  err.message = err.message || "internal server error";

  if (err.message) {
    res.status(status).send({
      status: false,
      message: err.message,
    });
  } else {
    res.status(500).send("there wwas an error");
  }
});

app.listen(PORT, () => {
  console.log(`your server is running on ${PORT}`);
});
