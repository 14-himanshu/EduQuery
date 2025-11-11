const mongoose = require("mongoose");
const Schema = mongoose.Schema;
const ObjectId = mongoose.ObjectId;
const User = new Schema({
  email: { type: String, unique: true },
  password: String,
  name: String,
});

const Todo = new Schema({
  title: String,
  done: Boolean,
  userId: ObjectId,
});
const UserModal = mongoose.model("users", User);
const TodoModal = mongoose.model("todos", Todo);

module.exports = {
  UserModal,
  TodoModal,
};
