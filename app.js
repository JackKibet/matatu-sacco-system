require('dotenv').config();
const express = require('express');
const mongoose = require('mongoose');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const ejs = require('ejs');
const path = require('path');
const cookieParser = require('cookie-parser');
const methodOverride = require('method-override');
const moment = require('moment');
const currencyFormatter = require('currency-formatter');
// Initialize Express
const app = express();

// Connect to MongoDB
mongoose.connect(process.env.MONGO_URI)
  .then(() => console.log('Connected to MongoDB'))
  .catch(err => console.error('Connection error:', err));

// Middleware
app.use(cookieParser());
app.use(express.urlencoded({ extended: true }));
app.use(express.json());
app.use(express.static('public'));
app.use(methodOverride('_method'));
app.set('view engine', 'ejs');
app.set('views', path.join(__dirname, 'views'));

// Models
// Expense Model (put with other models)
const Expense = mongoose.model('Expense', new mongoose.Schema({
  date: { type: Date, default: Date.now },
  category: { 
    type: String, 
    enum: ['fuel', 'maintenance', 'salaries', 'other'] 
  },
  amount: { type: Number, required: true },
  description: String,
  vehicle: { type: mongoose.Schema.Types.ObjectId, ref: 'Vehicle' },
  route: {  // ← THIS IS THE MISSING FIELD
    type: mongoose.Schema.Types.ObjectId, 
    ref: 'Route' 
  },
  sacco: { type: mongoose.Schema.Types.ObjectId, ref: 'User' }
}));
// Daily Revenue Model (put with other models)
const DailyRevenue = mongoose.model('DailyRevenue', new mongoose.Schema({
  date: { type: Date, default: Date.now },
  route: { type: mongoose.Schema.Types.ObjectId, ref: 'Route' },
  vehicle: { type: mongoose.Schema.Types.ObjectId, ref: 'Vehicle' },
  driver: { type: mongoose.Schema.Types.ObjectId, ref: 'Driver' },
  amount: { type: Number, required: true },
  expenses: { type: Number, default: 0 },
  collectedBy: { type: mongoose.Schema.Types.ObjectId, ref: 'Driver' },
  sacco: { type: mongoose.Schema.Types.ObjectId, ref: 'User' }
}));
// Route Management Model (put with your other models)
const Route = mongoose.model('Route', new mongoose.Schema({
  name: { type: String, required: true },
  startPoint: { type: String, required: true },
  endPoint: { type: String, required: true },
  stops: [{ 
    name: String,
    location: String,
    fareFromStart: Number 
  }],
  distance: Number,
  estimatedTime: Number,
  assignedVehicle: { type: mongoose.Schema.Types.ObjectId, ref: 'Vehicle' },
  assignedDriver: { type: mongoose.Schema.Types.ObjectId, ref: 'Driver' },
  active: { type: Boolean, default: true },
  sacco: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
  createdAt: { type: Date, default: Date.now }
}));
const userSchema = new mongoose.Schema({
  saccoName: { 
    type: String, 
    required: true,
    trim: true,
    minlength: 3,
    maxlength: 50
  },
  email: { 
    type: String, 
    required: true,
    unique: true,
    trim: true,
    lowercase: true,
    validate: {
      validator: function(v) {
        return /^\w+([\.-]?\w+)*@\w+([\.-]?\w+)*(\.\w{2,3})+$/.test(v);
      },
      message: props => `${props.value} is not a valid email address!`
    }
  },
  password: {
    type: String,
    required: true,
    minlength: 6
  }
});

userSchema.pre('save', async function(next) {
  if (this.isModified('password')) {
    this.password = await bcrypt.hash(this.password, 10);
  }
  next();
});

const User = mongoose.model('User', userSchema);

const vehicleSchema = new mongoose.Schema({
  registrationNumber: { type: String, required: true },
  make: String,
  model: String,
  year: Number,
  capacity: Number,
  sacco: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
  driver: { type: mongoose.Schema.Types.ObjectId, ref: 'Driver' }
});

const Vehicle = mongoose.model('Vehicle', vehicleSchema);

const Driver = mongoose.model('Driver', new mongoose.Schema({
  name: { type: String, required: true },
  licenseNumber: { type: String, required: true },
  phone: String,
  address: String,
  sacco: { type: mongoose.Schema.Types.ObjectId, ref: 'User' }
}));

// Auth Middleware
const auth = async (req, res, next) => {
  try {
    const token = req.cookies.token || req.header('Authorization')?.replace('Bearer ', '');
    if (!token) throw new Error();
    const decoded = jwt.verify(token, process.env.JWT_SECRET || 'matatusaccosecret');
    req.user = await User.findById(decoded.userId);
    if (!req.user) throw new Error();
    next();
  } catch (e) {
    res.redirect('/login');
  }
};

// Routes - Authentication
app.get('/login', (req, res) => {
  res.render('login', { 
    error: req.query.error,
    header: '<h1 class="text-center my-4">Matatu Sacco Login</h1>',
    footer: ''
  });
});

app.post('/login', async (req, res) => {
  try {
    const { email, password } = req.body;
    const user = await User.findOne({ email: email.trim().toLowerCase() }).select('+password');
    
    if (!user || !(await bcrypt.compare(password, user.password))) {
      return res.redirect('/login?error=Invalid+credentials');
    }

    const token = jwt.sign(
      { userId: user._id },
      process.env.JWT_SECRET || 'matatusaccosecret',
      { expiresIn: '1d' }
    );

    res.cookie('token', token, {
      httpOnly: true,
      secure: process.env.NODE_ENV === 'production',
      maxAge: 86400000
    }).redirect('/');
  } catch (error) {
    res.redirect('/login?error=Login+failed');
  }
});

app.get('/register', (req, res) => {
  res.render('register', { error: req.query.error });
});

app.post('/register', async (req, res) => {
  try {
    const { saccoName, email, password } = req.body;
    const hashedPassword = await bcrypt.hash(password, 10);
    const user = new User({ saccoName, email, password: hashedPassword });
    await user.save();
    
    const token = jwt.sign({ userId: user._id }, process.env.JWT_SECRET || 'matatusaccosecret');
    res.cookie('token', token).redirect('/');
  } catch (error) {
    res.redirect('/register?error=Registration+failed');
  }
});

app.get('/logout', (req, res) => {
  res.clearCookie('token').redirect('/login');
});

// Routes - Dashboard
app.get('/', auth, async (req, res) => {
  const [vehicles, drivers, routes, revenues] = await Promise.all([
    Vehicle.find({ sacco: req.user._id }),
    Driver.find({ sacco: req.user._id }),
    Route.find({ sacco: req.user._id }),
    DailyRevenue.find({ 
      sacco: req.user._id,
      date: { 
        $gte: new Date(new Date().setHours(0, 0, 0, 0)),
        $lt: new Date(new Date().setHours(23, 59, 59, 999))
      }
    })
  ]);

  
  res.render('index', { 
    user: req.user, 
    vehicles, 
    drivers,
     routes,
    todayRevenue: revenues.reduce((sum, r) => sum + r.amount, 0)
  ,
    header: `
      <header class="bg-primary text-white p-3">
        <h1>${req.user.saccoName} Sacco</h1>
        <nav>
            <a href="/" class="text-white mx-2">Home</a>
          <a href="/vehicles" class="text-white mx-2">Vehicles</a>
          <a href="/drivers" class="text-white mx-2">Drivers</a>
          <a href="/routes" class="text-white mx-2">Routes</a>
          <a href="/revenues" class="text-white mx-2">Revenue</a>
          <a href="/expenses" class="text-white mx-2">Expenses</a>
          <a href="/reports" class="text-white mx-2">Reports</a>
          <a href="/logout" class="text-white mx-2">Logout</a>
        </nav>
      </header>
    `,
    footer: `
      <footer class="bg-dark text-white p-3 mt-4 text-center">
        <p>&copy; ${new Date().getFullYear()} Matatu Sacco System</p>
      </footer>
    `
  });

});
// Routes - Vehicles (ordered from specific to general)
app.get('/vehicles/new', auth, (req, res) => {
  res.render('vehicles-new', {
    user: req.user,
    header: `
      <header style="background: #2c3e50; color: white; padding: 1rem;">
        <h1>${req.user.saccoName} - Register New Vehicle</h1>
        <nav>
          <a href="/" style="color: white; margin-right: 1rem;">Home</a>
          <a href="/vehicles" style="color: white; margin-right: 1rem;">Vehicles</a>
          <a href="/logout" style="color: white;">Logout</a>
        </nav>
      </header>
    `,
    footer: `
      <footer style="background: #2c3e50; color: white; text-align: center; padding: 1rem; margin-top: 2rem;">
        <p>&copy; ${new Date().getFullYear()} Matatu Sacco System</p>
      </footer>
    `
  });
});

app.post('/vehicles', auth, async (req, res) => {
  try {
    const vehicle = new Vehicle({ ...req.body, sacco: req.user._id });
    await vehicle.save();
    res.redirect('/vehicles');
  } catch (error) {
    res.redirect('/vehicles/new?error=Registration+failed');
  }
});

app.get('/vehicles/:id/edit', auth, async (req, res) => {
  try {
    const vehicle = await Vehicle.findOne({ _id: req.params.id, sacco: req.user._id });
    const drivers = await Driver.find({ sacco: req.user._id });
    
    res.render('vehicle-edit', {
      user: req.user,
      vehicle,
      drivers,
      header: `
        <header style="background: #2c3e50; color: white; padding: 1rem;">
          <h1>${req.user.saccoName} - Edit Vehicle</h1>
          <nav>
            <a href="/" style="color: white; margin-right: 1rem;">Home</a>
            <a href="/vehicles" style="color: white; margin-right: 1rem;">Vehicles</a>
            <a href="/logout" style="color: white;">Logout</a>
          </nav>
        </header>
      `,
      footer: `
        <footer style="background: #2c3e50; color: white; text-align: center; padding: 1rem; margin-top: 2rem;">
          <p>&copy; ${new Date().getFullYear()} Matatu Sacco System</p>
        </footer>
      `
    });
  } catch (error) {
    res.redirect('/vehicles?error=Vehicle+not+found');
  }
});

app.put('/vehicles/:id', auth, async (req, res) => {
  try {
    await Vehicle.updateOne(
      { _id: req.params.id, sacco: req.user._id },
      { ...req.body, registrationNumber: req.body.registrationNumber.toUpperCase() }
    );
    res.redirect(`/vehicles/${req.params.id}`);
  } catch (error) {
    res.redirect(`/vehicles/${req.params.id}/edit?error=Update+failed`);
  }
});

app.get('/vehicles/:id', auth, async (req, res) => {
  try {
    const vehicle = await Vehicle.findOne({ _id: req.params.id, sacco: req.user._id }).populate('driver');
    
    res.render('vehicle-detail', {
      user: req.user,
      vehicle,
      header: `
        <header style="background: #2c3e50; color: white; padding: 1rem;">
          <h1>${req.user.saccoName} - Vehicle Details</h1>
          <nav>
            <a href="/" style="color: white; margin-right: 1rem;">Home</a>
            <a href="/vehicles" style="color: white; margin-right: 1rem;">Vehicles</a>
            <a href="/logout" style="color: white;">Logout</a>
          </nav>
        </header>
      `,
      footer: `
        <footer style="background: #2c3e50; color: white; text-align: center; padding: 1rem; margin-top: 2rem;">
          <p>&copy; ${new Date().getFullYear()} Matatu Sacco System</p>
        </footer>
      `
    });
  } catch (error) {
    res.redirect('/vehicles?error=Vehicle+not+found');
  }
});

app.get('/vehicles', auth, async (req, res) => {
  const vehicles = await Vehicle.find({ sacco: req.user._id });
  res.render('vehicles', {
    user: req.user,
    vehicles,
    header: `
      <header class="bg-primary text-white p-3">
        <h1>${req.user.saccoName} Vehicles</h1>
        <nav>
          <a href="/" class="text-white mx-2">Home</a>
          <a href="/vehicles" class="text-white mx-2">Vehicles</a>
          <a href="/drivers" class="text-white mx-2">Drivers</a>
          <a href="/logout" class="text-white mx-2">Logout</a>
        </nav>
      </header>
    `,
    footer: `
      <footer class="bg-dark text-white p-3 mt-4 text-center">
        <p>&copy; ${new Date().getFullYear()} Matatu Sacco System</p>
      </footer>
    `
  });
});

// Routes - Drivers (ordered from specific to general)
app.get('/drivers/new', auth, (req, res) => {
  res.render('drivers-new', {
    user: req.user,
    header: `
      <header style="background: #2c3e50; color: white; padding: 1rem;">
        <h1>${req.user.saccoName} - Register New Driver</h1>
        <nav>
          <a href="/" style="color: white; margin-right: 1rem;">Home</a>
          <a href="/drivers" style="color: white; margin-right: 1rem;">Drivers</a>
          <a href="/logout" style="color: white;">Logout</a>
        </nav>
      </header>
    `,
    footer: `
      <footer style="background: #2c3e50; color: white; text-align: center; padding: 1rem; margin-top: 2rem;">
        <p>&copy; ${new Date().getFullYear()} Matatu Sacco System</p>
      </footer>
    `
  });
});

app.post('/drivers', auth, async (req, res) => {
  try {
    const driver = new Driver({ ...req.body, sacco: req.user._id });
    await driver.save();
    res.redirect('/drivers');
  } catch (error) {
    res.redirect('/drivers/new?error=Registration+failed');
  }
});

app.get('/drivers/:id/edit', auth, async (req, res) => {
  try {
    const driver = await Driver.findOne({ _id: req.params.id, sacco: req.user._id });
    
    res.render('driver-edit', {
      user: req.user,
      driver,
      header: `
        <header style="background: #2c3e50; color: white; padding: 1rem;">
          <h1>${req.user.saccoName} - Edit Driver</h1>
          <nav>
            <a href="/" style="color: white; margin-right: 1rem;">Home</a>
            <a href="/drivers" style="color: white; margin-right: 1rem;">Drivers</a>
            <a href="/logout" style="color: white;">Logout</a>
          </nav>
        </header>
      `,
      footer: `
        <footer style="background: #2c3e50; color: white; text-align: center; padding: 1rem; margin-top: 2rem;">
          <p>&copy; ${new Date().getFullYear()} Matatu Sacco System</p>
        </footer>
      `
    });
  } catch (error) {
    res.redirect('/drivers?error=Driver+not+found');
  }
});

app.put('/drivers/:id', auth, async (req, res) => {
  try {
    await Driver.updateOne(
      { _id: req.params.id, sacco: req.user._id },
      req.body
    );
    res.redirect(`/drivers/${req.params.id}`);
  } catch (error) {
    res.redirect(`/drivers/${req.params.id}/edit?error=Update+failed`);
  }
});

app.get('/drivers/:id', auth, async (req, res) => {
  try {
    const driver = await Driver.findOne({ _id: req.params.id, sacco: req.user._id });
    
    res.render('driver-detail', {
      user: req.user,
      driver,
      header: `
        <header style="background: #2c3e50; color: white; padding: 1rem;">
          <h1>${req.user.saccoName} - Driver Details</h1>
          <nav>
            <a href="/" style="color: white; margin-right: 1rem;">Home</a>
            <a href="/drivers" style="color: white; margin-right: 1rem;">Drivers</a>
            <a href="/logout" style="color: white;">Logout</a>
          </nav>
        </header>
      `,
      footer: `
        <footer style="background: #2c3e50; color: white; text-align: center; padding: 1rem; margin-top: 2rem;">
          <p>&copy; ${new Date().getFullYear()} Matatu Sacco System</p>
        </footer>
      `
    });
  } catch (error) {
    res.redirect('/drivers?error=Driver+not+found');
  }
});

app.get('/drivers', auth, async (req, res) => {
  const drivers = await Driver.find({ sacco: req.user._id });
  res.render('drivers', {
    user: req.user,
    drivers,
    header: `
      <header class="bg-primary text-white p-3">
        <h1>${req.user.saccoName} Drivers</h1>
        <nav>
          <a href="/" class="text-white mx-2">Home</a>
          <a href="/vehicles" class="text-white mx-2">Vehicles</a>
          <a href="/drivers" class="text-white mx-2">Drivers</a>
          <a href="/logout" class="text-white mx-2">Logout</a>
        </nav>
      </header>
    `,
    footer: `
      <footer class="bg-dark text-white p-3 mt-4 text-center">
        <p>&copy; ${new Date().getFullYear()} Matatu Sacco System</p>
      </footer>
    `
  });
});
// ===== ROUTE MANAGEMENT ROUTES ===== (put after driver routes)
app.get('/routes', auth, async (req, res) => {
  const routes = await Route.find({ sacco: req.user._id })
    .populate('assignedVehicle')
    .populate('assignedDriver');
  
  res.render('routes', { 
    user: req.user,
    routes,
    header: `<header class="bg-primary text-white p-3">
        <h1>${req.user.saccoName} Drivers</h1>
        <nav>
          <a href="/" class="text-white mx-2">Home</a>
          <a href="/vehicles" class="text-white mx-2">Vehicles</a>
          <a href="/drivers" class="text-white mx-2">Drivers</a>
          <a href="/logout" class="text-white mx-2">Logout</a>
        </nav>
      </header>`,
    footer: `<footer class="bg-dark text-white p-3 mt-4 text-center">
        <p>&copy; ${new Date().getFullYear()} Matatu Sacco System</p>
      </footer>`
  });
});

app.get('/routes/new', auth, async (req, res) => {
  const [vehicles, drivers] = await Promise.all([
    Vehicle.find({ sacco: req.user._id }),
    Driver.find({ sacco: req.user._id })
  ]);
  
  res.render('routes/new', { 
    user: req.user,
    vehicles,
    drivers
  });
});
// View single route
app.get('/routes/:id', auth, async (req, res) => {
  try {
    const route = await Route.findOne({ 
      _id: req.params.id, 
      sacco: req.user._id 
    }).populate('assignedVehicle').populate('assignedDriver');

    if (!route) {
      return res.status(404).render('error', { 
        message: 'Route not found',
        header: `<header class="bg-primary text-white p-3">
        <h1>${req.user.saccoName} Drivers</h1>
        <nav>
          <a href="/" class="text-white mx-2">Home</a>
          <a href="/vehicles" class="text-white mx-2">Vehicles</a>
          <a href="/drivers" class="text-white mx-2">Drivers</a>
          <a href="/logout" class="text-white mx-2">Logout</a>
        </nav>
      </header>`,        
        footer: `<footer class="bg-dark text-white p-3 mt-4 text-center">
        <p>&copy; ${new Date().getFullYear()} Matatu Sacco System</p>
      </footer>`
      });
    }

    res.render('routes/show', {
      user: req.user,
      route,
      header: `<header class="bg-primary text-white p-3">
        <h1>${req.user.saccoName} Drivers</h1>
        <nav>
          <a href="/" class="text-white mx-2">Home</a>
          <a href="/vehicles" class="text-white mx-2">Vehicles</a>
          <a href="/drivers" class="text-white mx-2">Drivers</a>
          <a href="/logout" class="text-white mx-2">Logout</a>
        </nav>
      </header>`,
      footer: `<footer class="bg-dark text-white p-3 mt-4 text-center">
        <p>&copy; ${new Date().getFullYear()} Matatu Sacco System</p>
      </footer>`
    });
  } catch (error) {
    res.status(500).render('error', {
      message: 'Failed to load route',
      error: error,
      header: '',
      footer: ''
    });
  }
});
app.post('/routes', auth, async (req, res) => {
  try {
    const route = new Route({ ...req.body, sacco: req.user._id });
    await route.save();
    res.redirect('/routes');
  } catch (error) {
    res.redirect('/routes/new?error=Failed+to+create+route');
  }
});
// ===== DAILY REVENUE ROUTES ===== (put after route routes)
app.get('/revenues', auth, async (req, res) => {
  try {
    const { startDate, endDate } = req.query;
    
    // Build query with date filtering
    const query = { sacco: req.user._id };
    if (startDate || endDate) {
      query.date = {};
      if (startDate) query.date.$gte = new Date(startDate);
      if (endDate) query.date.$lte = new Date(endDate);
    }

    const revenues = await DailyRevenue.find(query)
      .populate('route')
      .populate('vehicle')
      .populate('driver')
      .sort({ date: -1 });

    res.render('revenues/index', {
      user: req.user,
      revenues,
      filters: {  // Add this filters object
        startDate: startDate || '',
        endDate: endDate || ''
      },
      formatCurrency: (amount) => {  // Add currency formatter
        return new Intl.NumberFormat('en-KE', {
          style: 'currency',
          currency: 'KES'
        }).format(amount || 0);
      },
      header: `...your header...`,
      footer: `...your footer...`
    });

  } catch (error) {
    console.error('Revenue listing error:', error);
    res.redirect('/revenues?error=Failed+to+load+revenues');
  }
});

app.post('/revenues', auth, async (req, res) => {
  try {
    const revenue = new DailyRevenue({ 
      ...req.body,
      sacco: req.user._id,
      date: new Date(req.body.date)
    });
    await revenue.save();
    res.redirect('/revenues');
  } catch (error) {
    res.redirect('/revenues/new?error=Failed+to+save');
  }
});
// New revenue form
app.get('/revenues/new', auth, async (req, res) => {
  try {
    const [routes, vehicles, drivers] = await Promise.all([
      Route.find({ sacco: req.user._id }),
      Vehicle.find({ sacco: req.user._id }),
      Driver.find({ sacco: req.user._id })
    ]);

    res.render('revenues/new', {
      user: req.user,
      routes,
      vehicles,
      drivers,
      today: new Date().toISOString().split('T')[0],
      header: `<header class="bg-primary text-white p-3">
        <h1>${req.user.saccoName} Drivers</h1>
        <nav>
          <a href="/" class="text-white mx-2">Home</a>
          <a href="/vehicles" class="text-white mx-2">Vehicles</a>
          <a href="/drivers" class="text-white mx-2">Drivers</a>
          <a href="/logout" class="text-white mx-2">Logout</a>
        </nav>
      </header>`,
      footer: `<footer class="bg-dark text-white p-3 mt-4 text-center">
        <p>&copy; ${new Date().getFullYear()} Matatu Sacco System</p>
      </footer>`
    });
  } catch (error) {
    res.redirect('/revenues?error=Failed+to+load+form');
  }
});
// ===== EXPENSE ROUTES ===== (put after revenue routes)
app.get('/expenses', auth, async (req, res) => {
  const expenses = await Expense.find({ sacco: req.user._id })
    .populate('vehicle');
  
  res.render('expenses', { 
    user: req.user,
    expenses 
  });
});

app.post('/expenses', auth, async (req, res) => {
  try {
    const expense = new Expense({ 
      ...req.body,
      sacco: req.user._id 
    });
    await expense.save();
    res.redirect('/expenses');
  } catch (error) {
    res.redirect('/expenses/new?error=Failed+to+save');
  }
});
// New expense form
app.get('/expenses/new', auth, async (req, res) => {
  try {
    const [vehicles, routes] = await Promise.all([
      Vehicle.find({ sacco: req.user._id }),
      Route.find({ sacco: req.user._id })
    ]);

    res.render('expenses/new', {
      user: req.user,
      vehicles,
      routes,
      today: new Date().toISOString().split('T')[0],
      header: `<header class="bg-primary text-white p-3">
        <h1>${req.user.saccoName} Drivers</h1>
        <nav>
          <a href="/" class="text-white mx-2">Home</a>
          <a href="/vehicles" class="text-white mx-2">Vehicles</a>
          <a href="/drivers" class="text-white mx-2">Drivers</a>
          <a href="/logout" class="text-white mx-2">Logout</a>
        </nav>
      </header>`,
      footer: `<footer class="bg-dark text-white p-3 mt-4 text-center">
        <p>&copy; ${new Date().getFullYear()} Matatu Sacco System</p>
      </footer>`
    });
  } catch (error) {
    res.redirect('/expenses?error=Failed+to+load+form');
  }
});
// ===== REPORT ROUTES ===== (put near end before error handling)
app.get('/reports', auth, async (req, res) => {
  const [revenues, expenses] = await Promise.all([
    DailyRevenue.find({ sacco: req.user._id }),
    Expense.find({ sacco: req.user._id })
  ]);
  
  res.render('reports', {
    user: req.user,
    totalRevenue: revenues.reduce((sum, r) => sum + r.amount, 0),
    totalExpenses: expenses.reduce((sum, e) => sum + e.amount, 0)
  });
});
// Revenue report
// Revenue Report Route - Fully Implemented
app.get('/reports/revenue', auth, async (req, res) => {
  try {
    const { startDate, endDate } = req.query;
    const saccoId = req.user._id;

    // Build query with date filtering
    const query = { sacco: saccoId };
    if (startDate || endDate) {
      query.date = {};
      if (startDate) query.date.$gte = new Date(startDate);
      if (endDate) query.date.$lte = new Date(endDate);
    }

    // Fetch revenue data
    const revenues = await DailyRevenue.find(query)
      .populate('route', 'name startPoint endPoint')
      .populate('vehicle', 'registrationNumber make')
      .sort({ date: -1 });

    // Calculate summary totals
    const summary = {
      totalRevenue: revenues.reduce((sum, rev) => sum + rev.amount, 0),
      totalExpenses: revenues.reduce((sum, rev) => sum + (rev.expenses || 0), 0),
      count: revenues.length
    };
    summary.netProfit = summary.totalRevenue - summary.totalExpenses;

    // Create currency formatting function
    const formatCurrency = (amount) => {
      return new Intl.NumberFormat('en-KE', {
        style: 'currency',
        currency: 'KES',
        minimumFractionDigits: 2,
        maximumFractionDigits: 2
      }).format(amount);
    };

    res.render('reports/revenue', {
      user: req.user,
      revenues,
      summary,
      filters: {
        startDate: startDate || '',
        endDate: endDate || ''
      },
      moment: require('moment'),
      formatCurrency, // Pass the formatting function
      header: `
        <header class="navbar navbar-expand-lg navbar-dark bg-primary mb-4">
          <div class="container">
            <a class="navbar-brand" href="/">${req.user.saccoName} Revenue Report</a>
          </div>
        </header>
      `,
      footer: `
        <footer class="bg-dark text-white py-3 mt-5">
          <div class="container text-center">
            <p>&copy; ${new Date().getFullYear()} ${req.user.saccoName}</p>
          </div>
        </footer>
      `
    });

  } catch (error) {
    console.error('Revenue Report Error:', error);
    res.status(500).render('error', {
      message: 'Failed to generate revenue report',
      error: process.env.NODE_ENV === 'development' ? error : null,
      header: '',
      footer: ''
    });
  }
});
// Expense Report
app.get('/reports/expenses', auth, async (req, res) => {
  try {
    const { startDate, endDate, category } = req.query;
    const saccoId = req.user._id;

    // Build query
    const query = { sacco: saccoId };
    
    // Date filtering
    if (startDate || endDate) {
      query.date = {};
      if (startDate) query.date.$gte = new Date(startDate);
      if (endDate) query.date.$lte = new Date(endDate);
    }
    
    // Category filtering
    if (category && category !== 'all') {
      query.category = category;
    }

    // Get expense data
    const expenses = await Expense.find(query)
      .populate('vehicle', 'registrationNumber make')
      .populate('route', 'name')
      .sort({ date: -1 });

    // Calculate totals
    const totals = {
      amount: expenses.reduce((sum, exp) => sum + exp.amount, 0),
      count: expenses.length
    };

    res.render('reports/expenses', {
      user: req.user,
      expenses,
      totals,
      startDate: startDate || '',
      endDate: endDate || '',
      selectedCategory: category || 'all',
      categories: ['fuel', 'maintenance', 'salaries', 'other'],
      header: `...your header...`,
      footer: `...your footer...`
    });

  } catch (error) {
    console.error('Expense Report Error:', error);
    res.redirect('/reports?error=' + encodeURIComponent(error.message));
  }
});

// Performance Report Route
app.get('/reports/performance', auth, async (req, res) => {
  try {
    const { period } = req.query; // daily, weekly, monthly
    const saccoId = req.user._id;

    // Calculate date ranges based on period
    const dateRange = calculateDateRange(period || 'monthly');
    
    // Get performance data
    const [revenues, expenses, vehicles, drivers] = await Promise.all([
      DailyRevenue.find({
        sacco: saccoId,
        date: { $gte: dateRange.start, $lte: dateRange.end }
      }),
      Expense.find({
        sacco: saccoId,
        date: { $gte: dateRange.start, $lte: dateRange.end }
      }),
      Vehicle.find({ sacco: saccoId }),
      Driver.find({ sacco: saccoId })
    ]);

    // Calculate performance metrics
    const performance = {
      period: period || 'monthly',
      totalRevenue: revenues.reduce((sum, rev) => sum + rev.amount, 0),
      totalExpenses: expenses.reduce((sum, exp) => sum + exp.amount, 0),
      vehicleUtilization: calculateUtilization(vehicles, revenues),
      driverPerformance: calculateDriverPerformance(drivers, revenues),
      topRoutes: calculateTopRoutes(revenues),
      profitMargin: 0 // Will calculate below
    };
    performance.profitMargin = performance.totalRevenue > 0 
      ? ((performance.totalRevenue - performance.totalExpenses) / performance.totalRevenue) * 100 
      : 0;

    res.render('reports/performance', {
      user: req.user,
      performance,
      filters: { period: period || 'monthly' },
      formatCurrency: (amount) => new Intl.NumberFormat('en-KE', {
        style: 'currency',
        currency: 'KES'
      }).format(amount || 0),
      formatPercent: (value) => `${value.toFixed(1)}%`,
      moment: require('moment'),
      header: `...your header...`,
      footer: `...your footer...`
    });

  } catch (error) {
    console.error('Performance Report Error:', error);
    res.status(500).render('error', {
      message: 'Failed to generate performance report',
      error: process.env.NODE_ENV === 'development' ? error : null
    });
  }
});

// Helper functions
function calculateDateRange(period) {
  const now = new Date();
  switch (period) {
    case 'daily':
      return {
        start: new Date(now.setHours(0, 0, 0, 0)),
        end: new Date(now.setHours(23, 59, 59, 999))
      };
    case 'weekly':
      return {
        start: new Date(now.setDate(now.getDate() - now.getDay())),
        end: new Date(now.setDate(now.getDate() - now.getDay() + 6))
      };
    default: // monthly
      return {
        start: new Date(now.getFullYear(), now.getMonth(), 1),
        end: new Date(now.getFullYear(), now.getMonth() + 1, 0)
      };
  }
}

function calculateUtilization(vehicles, revenues) {
  const vehicleMap = {};
  vehicles.forEach(v => vehicleMap[v._id] = { ...v.toObject(), tripCount: 0 });
  
  revenues.forEach(rev => {
    if (rev.vehicle && vehicleMap[rev.vehicle]) {
      vehicleMap[rev.vehicle].tripCount++;
    }
  });

  return Object.values(vehicleMap).map(v => ({
    vehicle: v.registrationNumber,
    make: v.make,
    utilization: (v.tripCount / revenues.length) * 100 || 0
  })).sort((a, b) => b.utilization - a.utilization);
}

function calculateDriverPerformance(drivers, revenues) {
  // Similar to vehicle utilization but for drivers
}

function calculateTopRoutes(revenues) {
  // Calculate and return top performing routes
}
app.get('/routes/new', auth, async (req, res) => {
  try {
    const [vehicles, drivers] = await Promise.all([
      Vehicle.find({ sacco: req.user._id }),
      Driver.find({ sacco: req.user._id })
    ]);
    
    res.render('routes/new', {  // Changed from 'routes-new' to 'routes/new'
      user: req.user,
      vehicles,
      drivers,
      header: `<header class="bg-primary text-white p-3">
        <h1>${req.user.saccoName} Drivers</h1>
        <nav>
          <a href="/" class="text-white mx-2">Home</a>
          <a href="/vehicles" class="text-white mx-2">Vehicles</a>
          <a href="/drivers" class="text-white mx-2">Drivers</a>
          <a href="/logout" class="text-white mx-2">Logout</a>
        </nav>
      </header>`,
      footer: `<footer class="bg-dark text-white p-3 mt-4 text-center">
        <p>&copy; ${new Date().getFullYear()} Matatu Sacco System</p>
      </footer>`
    });
  } catch (error) {
    res.redirect('/routes?error=Failed+to+load+form');
  }
});
// Debug route - Add this temporarily
app.get('/debug/revenue', auth, async (req, res) => {
  try {
    console.log("Attempting to fetch revenue data...");
    const testData = await DailyRevenue.find({ sacco: req.user._id })
      .limit(5)
      .populate('route')
      .populate('vehicle');
      
    console.log("Test data found:", testData);
    res.json({
      success: true,
      count: testData.length,
      data: testData
    });
  } catch (err) {
    console.error("DEBUG ERROR:", err);
    res.status(500).json({
      success: false,
      error: err.message
    });
  }
});
// Error Handling Middleware
app.use((err, req, res, next) => {
  console.error('Error:', err);
  
  // Ensure we always have a proper error object
  const errorObj = err instanceof Error ? err : new Error(String(err));
  
  res.status(500).render('error', {
    message: errorObj.message || 'Something went wrong',
    error: process.env.NODE_ENV === 'development' ? errorObj : null,
    header: '',
    footer: ''
  });
});

// Start Server
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`Server running on port ${PORT}`));