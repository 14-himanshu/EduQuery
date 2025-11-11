import axios from "axios";

const api = axios.create({
  baseURL: "https://eduquery-ifh6.onrender.com", // backend server
});

export default api;
