const userModel = require("../models/userModel");
const projectModel = require("../models/projectModel");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");

const secret = "secret"; // you can later use process.env.JWT_SECRET

// Helper to return starter code for different languages
function getStartupCode(language) {
  switch (language.toLowerCase()) {
    case "python":
      return 'print("Hello World")';
    case "java":
      return 'public class Main { public static void main(String[] args) { System.out.println("Hello World"); } }';
    case "javascript":
      return 'console.log("Hello World");';
    case "cpp":
      return '#include <iostream>\n\nint main() {\n    std::cout << "Hello World" << std::endl;\n    return 0;\n}';
    case "c":
      return '#include <stdio.h>\n\nint main() {\n    printf("Hello World\\n");\n    return 0;\n}';
    case "go":
      return 'package main\n\nimport "fmt"\n\nfunc main() {\n    fmt.Println("Hello World")\n}';
    case "bash":
      return 'echo "Hello World"';
    default:
      return "Language not supported";
  }
}

// --------------------- SIGN UP ---------------------
exports.signUp = async (req, res) => {
  try {
    const { email, pwd, fullName } = req.body;
    if (!email || !pwd || !fullName) {
      return res.status(400).json({ success: false, msg: "Missing required fields" });
    }

    const emailExists = await userModel.findOne({ email });
    if (emailExists) {
      return res.status(400).json({ success: false, msg: "Email already exists" });
    }

    bcrypt.genSalt(12, (err, salt) => {
      if (err) return res.status(500).json({ success: false, msg: err.message });
      bcrypt.hash(pwd, salt, async (err, hash) => {
        if (err) return res.status(500).json({ success: false, msg: err.message });

        await userModel.create({
          email,
          password: hash,
          fullName
        });

        return res.status(200).json({
          success: true,
          msg: "User created successfully"
        });
      });
    });
  } catch (error) {
    res.status(500).json({ success: false, msg: error.message });
  }
};

// --------------------- LOGIN ---------------------
exports.login = async (req, res) => {
  try {
    const { email, pwd } = req.body;
    if (!email || !pwd) {
      return res.status(400).json({ success: false, msg: "Missing email or password" });
    }

    const user = await userModel.findOne({ email });
    if (!user) {
      return res.status(404).json({ success: false, msg: "User not found" });
    }

    bcrypt.compare(pwd, user.password, (err, result) => {
      if (err) return res.status(500).json({ success: false, msg: err.message });
      if (result) {
        const token = jwt.sign({ userId: user._id }, secret, { expiresIn: "1h" });
        return res.status(200).json({
          success: true,
          msg: "User logged in successfully",
          token
        });
      } else {
        return res.status(401).json({ success: false, msg: "Invalid password" });
      }
    });
  } catch (error) {
    return res.status(500).json({ success: false, msg: error.message });
  }
};

// --------------------- CREATE PROJECT ---------------------
exports.createProj = async (req, res) => {
  try {
    console.log("Incoming body in createProj:", req.body);

    const { name, projLanguage, token, version } = req.body;
    if (!token) {
      return res.status(400).json({ success: false, msg: "Token is required" });
    }

    let decoded;
    try {
      decoded = jwt.verify(token, secret);
    } catch (err) {
      return res.status(401).json({ success: false, msg: "Invalid or expired token" });
    }

    const user = await userModel.findOne({ _id: decoded.userId });
    if (!user) {
      return res.status(404).json({ success: false, msg: "User not found" });
    }

    const project = await projectModel.create({
      name,
      projLanguage,
      createdBy: user._id,
      code: getStartupCode(projLanguage),
      version
    });

    return res.status(200).json({
      success: true,
      msg: "Project created successfully",
      projectId: project._id
    });
  } catch (error) {
    console.error("Error in createProj:", error);
    return res.status(500).json({ success: false, msg: error.message });
  }
};

// --------------------- SAVE PROJECT ---------------------
exports.saveProject = async (req, res) => {
  try {
    const { token, projectId, code } = req.body;
    if (!token) {
      return res.status(400).json({ success: false, msg: "Token is required" });
    }

    let decoded;
    try {
      decoded = jwt.verify(token, secret);
    } catch (err) {
      return res.status(401).json({ success: false, msg: "Invalid or expired token" });
    }

    const user = await userModel.findOne({ _id: decoded.userId });
    if (!user) {
      return res.status(404).json({ success: false, msg: "User not found" });
    }

    await projectModel.findOneAndUpdate({ _id: projectId }, { code });

    return res.status(200).json({ success: true, msg: "Project saved successfully" });
  } catch (error) {
    console.error(error);
    return res.status(500).json({ success: false, msg: error.message });
  }
};

// --------------------- GET PROJECTS ---------------------
exports.getProjects = async (req, res) => {
  try {
    const { token } = req.body;
    if (!token) {
      return res.status(400).json({ success: false, msg: "Token is required" });
    }

    let decoded;
    try {
      decoded = jwt.verify(token, secret);
    } catch (err) {
      return res.status(401).json({ success: false, msg: "Invalid or expired token" });
    }

    const user = await userModel.findOne({ _id: decoded.userId });
    if (!user) {
      return res.status(404).json({ success: false, msg: "User not found" });
    }

    const projects = await projectModel.find({ createdBy: user._id });

    return res.status(200).json({
      success: true,
      msg: "Projects fetched successfully",
      projects
    });
  } catch (error) {
    return res.status(500).json({ success: false, msg: error.message });
  }
};

// --------------------- GET PROJECT ---------------------
exports.getProject = async (req, res) => {
  try {
    const { token, projectId } = req.body;
    if (!token) {
      return res.status(400).json({ success: false, msg: "Token is required" });
    }

    let decoded;
    try {
      decoded = jwt.verify(token, secret);
    } catch (err) {
      return res.status(401).json({ success: false, msg: "Invalid or expired token" });
    }

    const user = await userModel.findOne({ _id: decoded.userId });
    if (!user) {
      return res.status(404).json({ success: false, msg: "User not found" });
    }

    const project = await projectModel.findOne({ _id: projectId });
    if (!project) {
      return res.status(404).json({ success: false, msg: "Project not found" });
    }

    return res.status(200).json({
      success: true,
      msg: "Project fetched successfully",
      project
    });
  } catch (error) {
    return res.status(500).json({ success: false, msg: error.message });
  }
};

// --------------------- DELETE PROJECT ---------------------
exports.deleteProject = async (req, res) => {
  try {
    const { token, projectId } = req.body;
    if (!token) {
      return res.status(400).json({ success: false, msg: "Token is required" });
    }

    let decoded;
    try {
      decoded = jwt.verify(token, secret);
    } catch (err) {
      return res.status(401).json({ success: false, msg: "Invalid or expired token" });
    }

    const user = await userModel.findOne({ _id: decoded.userId });
    if (!user) {
      return res.status(404).json({ success: false, msg: "User not found" });
    }

    await projectModel.findOneAndDelete({ _id: projectId });

    return res.status(200).json({ success: true, msg: "Project deleted successfully" });
  } catch (error) {
    return res.status(500).json({ success: false, msg: error.message });
  }
};

// --------------------- EDIT PROJECT ---------------------
exports.editProject = async (req, res) => {
  try {
    const { token, projectId, name } = req.body;
    if (!token) {
      return res.status(400).json({ success: false, msg: "Token is required" });
    }

    let decoded;
    try {
      decoded = jwt.verify(token, secret);
    } catch (err) {
      return res.status(401).json({ success: false, msg: "Invalid or expired token" });
    }

    const user = await userModel.findOne({ _id: decoded.userId });
    if (!user) {
      return res.status(404).json({ success: false, msg: "User not found" });
    }

    const project = await projectModel.findOne({ _id: projectId });
    if (!project) {
      return res.status(404).json({ success: false, msg: "Project not found" });
    }

    project.name = name;
    await project.save();

    return res.status(200).json({ success: true, msg: "Project edited successfully" });
  } catch (error) {
    return res.status(500).json({ success: false, msg: error.message });
  }
};
