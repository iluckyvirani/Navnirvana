import { Router } from "express";
const router = Router();

// import all controller 
import * as controller from '../controllers/appController.js';
import { getuser } from '../controllers/appController.js';
import { updateUser } from '../controllers/appController.js';
// import {createContactRequest} '../controllers/appController.js'
import Auth, { localVariables } from '../middleware/auth.js';
// POST Methods
router.route('/register').post(controller.register);// register user
//router.route('/registerMail').post(); // send the email
router.route('/authenticate').post((req, res) => res.end()); // authenticate user
router.route('/login').post(controller.verifyUser, controller.login); // login in app

// GET Methods
router.route('/user/:name').get(getuser); //user with username 
router.route('/generatepasswordOTP').get(controller.verifyUser, localVariables, controller.generatepasswordOTP); // generate random OTP
router.route('/verifyOTP').get(controller.verifyOTP); // verify generated OTP
// router.route('/createResetSession').get(controller.createResetSession); // reset all the variables
router.route('/getalluser').get(controller.getAllUsers); // Route to get all users
// PUT Methods
router.route('/updateuser').put(Auth, updateUser); // is use to update the user profile
router.route('/resetPassword').put(controller.resetPassword); // use to reset password
router.route('/updatepassword').put(controller.updatePassword);


router.route('/admin/register').post(controller.adminregister);// register admin
router.route('/admin/authenticate').post((req, res) => res.end()); // authenticate admin
router.route('/admin/login').post(controller.verifyAdmin, controller.adminlogin); // login in app


// GET Methods
// router.route('/admin/:name').get( getuser); //user with username 

router.route('/getalladmin').get(controller.getAllAdmin); // Route to get all users





// call request 

router.route('/contact').post(Auth, controller.createContactRequest);

router.route('/contact').get(Auth, controller.getAllContactRequests);
router.route('/contact/:requestId').get(Auth, controller.getContactRequestById);
router.patch('/contact/:requestId/status', Auth, controller.updateContactRequestStatus);



export default router;