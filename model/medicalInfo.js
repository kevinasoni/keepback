const mongoose = require("mongoose");

const MedicalInfoSchema = new mongoose.Schema({

  doctorName: {
    type: String
  },

  prescriptions: {
    type: String
  },

  medicalReport: {
    type: String
  }

});

module.exports = mongoose.model("MedicalInfo", MedicalInfoSchema);