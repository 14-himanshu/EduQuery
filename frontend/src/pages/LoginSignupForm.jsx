import React, { useState } from "react";
import "./LoginSignupForm.css"; 
import api from "../api/axiosConfig.js";

const LoginSignupForm = () => {
  const [isLogin, setIsLogin] = useState(true);
  const [formData, setFormData] = useState({
    name: "",
    email: "",
    password: "",
  });
  const [message, setMessage] = useState("");

  const handleChange = (e) =>
    setFormData({ ...formData, [e.target.name]: e.target.value });

  const handleSubmit = async (e) => {
    e.preventDefault();

    try {
      if (isLogin) {
        const res = await api.post("/signin", {
          email: formData.email,
          password: formData.password,
        });
        localStorage.setItem("token", res.data.token);
        setMessage("Login successful!");
      } else {
        const res = await api.post("/signup", {
          name: formData.name,
          email: formData.email,
          password: formData.password,
        });
        setMessage(res.data.message || "Signup successful!");
      }
    } catch (err) {
      if (err.response) setMessage(`${err.response.data.message}`);
      else setMessage("Server not responding");
    }
  };

  return (
    <div className="form-container">
      <div className="form-card">
        <h2 className="form-title">{isLogin ? "Login Form" : "Signup Form"}</h2>

        <div className="tab-buttons">
          <button
            className={`tab ${isLogin ? "active" : ""}`}
            onClick={() => setIsLogin(true)}
          >
            Login
          </button>
          <button
            className={`tab ${!isLogin ? "active" : ""}`}
            onClick={() => setIsLogin(false)}
          >
            Signup
          </button>
        </div>

        <form className="form" onSubmit={handleSubmit}>
          {!isLogin && (
            <input
              type="text"
              name="name"
              placeholder="Full Name"
              className="input-field"
              onChange={handleChange}
              required
            />
          )}
          <input
            type="email"
            name="email"
            placeholder="Email Address"
            className="input-field"
            onChange={handleChange}
            required
          />
          <input
            type="password"
            name="password"
            placeholder="Password"
            className="input-field"
            onChange={handleChange}
            required
          />

          {isLogin && (
            <a href="/forgotpassword" className="forgot-link">
              Forgot password?
            </a>
          )}

          <button type="submit" className="submit-btn">
            {isLogin ? "Login" : "Signup"}
          </button>
        </form>

        {message && <p className="message-text">{message}</p>}

        <p className="bottom-text">
          {isLogin ? (
            <>
              Create an account{" "}
              <span className="toggle-link" onClick={() => setIsLogin(false)}>
                Signup now
              </span>
            </>
          ) : (
            <>
              Already have an account?{" "}
              <span className="toggle-link" onClick={() => setIsLogin(true)}>
                Login now
              </span>
            </>
          )}
        </p>
      </div>
    </div>
  );
};

export default LoginSignupForm;
