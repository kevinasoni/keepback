const express = require("express");
const router = express.Router();
const multer = require("multer");
const MedicalInfo = require("../models/MedicalInfo");


// Multer Storage Setup
const storage = multer.diskStorage({
  destination: function (req, file, cb) {
    cb(null, "uploads/");
  },

  filename: function (req, file, cb) {
    cb(null, Date.now() + "-" + file.originalname);
  }
});

const upload = multer({ storage });


// POST medical record with file
router.post("/", upload.single("medicalReportsFile"), async (req, res) => {

  try {

    const newRecord = new MedicalInfo({
      doctorName: req.body.doctorName,
      prescriptions: req.body.prescriptions,
      medicalReport: req.file ? req.file.filename : null
    });

    await newRecord.save();

    res.json(newRecord);

  } catch (error) {
    res.status(500).json({ error: error.message });
  }

});


// GET all medical records
router.get("/", async (req, res) => {

  try {

    const records = await MedicalInfo.find();

    res.json(records);

  } catch (error) {
    res.status(500).json({ error: error.message });
  }

});

module.exports = router;