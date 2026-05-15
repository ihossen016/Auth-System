import { Router } from "express";
import * as authController from "../controllers/auth.controller.js";

const authRouter = Router();

/**
 * @route POST /api/auth/register
 * @desc Register a new user
 * @access Public
 */
authRouter.post("/register", authController.register);

/**
 * @route GET /api/auth/get-me
 * @desc Get current user info
 * @access Private
 */
authRouter.get("/get-me", authController.getMe);

/**
 * @route GET /api/auth/refresh-token
 * @desc Refresh access token using refresh token
 * @access Public (but requires valid refresh token in cookie)
 */
authRouter.get("/refresh-token", authController.refreshToken);

export default authRouter;
