const express = require('express');
const { PrismaClient } = require("@prisma/client");
const app = express();
const prisma = new PrismaClient();
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const dotenv = require('dotenv');
const PORT = 3000;
const SECRET_KEY = process.env.SECRET_KEY;

dotenv.config();
app.use(express.json());

app.post('/register', async (req, res, next) => {
    const { email, password } = req.body;
    const hashedPassword = await bcrypt.hash(password, 10);
  
    try {
      const newUser = await prisma.user.create({
        data: {
          email,
          password: hashedPassword,
        },
      });
      res.json({ message: 'User registered successfully', user: newUser });
    } catch (error) {
      next(error);
    }
  });
  
app.post('/login', async (req, res) => {
    const { email, password } = req.body;
  
    const user = await prisma.user.findUnique({
      where: { email },
    });
  
    if (!user) {
      return res.status(404).json({ error: 'User not found' });
    }
  
    const passwordMatch = await bcrypt.compare(password, user.password);
  
    if (!passwordMatch) {
      return res.status(401).json({ error: 'Incorrect password' });
    }
  
    const token = jwt.sign({ userId: user.id }, SECRET_KEY, { expiresIn: '1h' });
  
    res.json({ message: 'Login successful', token });
  });
  
const authenticateToken = (req, res, next) => {
    const token = req.header('Authorization');
    if (!token) return res.status(400).json({ error: 'Unauthorized' });
  
    jwt.verify(token, SECRET_KEY, (err, user) => {
      if (err) return res.status(403).json({ error: 'Forbidden' });
  
      req.user = user;
      next();
    });
  };
  
app.get('/tasks', authenticateToken, async (req, res) => {
    const tasks = await prisma.task.findMany({
      where: { userId: req.user.userId },
    });
    res.json(tasks);
  });
  
app.post('/tasks',  authenticateToken, async (req, res) => {
    const { title, description } = req.body;
    const newTask = await prisma.task.create({
      data: {
        title,
        description,
        userId: req.user.userId,
      },
    });
    res.json(newTask);
  });
  
  app.put('/tasks/:id', authenticateToken, async (req, res) => {
    const id = parseInt(req.params.id);
    const { title, description, completed } = req.body;
    const updatedTask = await prisma.task.update({
      where: { id },
      data: { title, description, completed },
    });
    res.json(updatedTask);
  });
  
  app.delete('/tasks/:id', authenticateToken, async (req, res) => {
    const id = parseInt(req.params.id);
    await prisma.task.delete({
      where: { id },
    });
    res.json({ message: 'Task deleted successfully' });
  });
  
  app.listen(PORT, () => {
    console.log(`Server is running on http://localhost:${PORT}`);
  });
