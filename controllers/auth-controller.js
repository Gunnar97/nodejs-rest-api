import User from "../models/User.js";
import bcrypt from "bcrypt";
import jwt from "jsonwebtoken";
import fs from "fs/promises";
import path from "path";
import gravatar from "gravatar";
import Jimp from "jimp";
import { nanoid } from "nanoid";

import { HttpError, sendEmail } from "../helpers/index.js";
import { ctrlWrapper } from "../decorators/index.js";

const { JWT_SECRET, BASE_URL } = process.env;
const avatarsPath = path.resolve("public", "avatars");

const signup = async (req, res) => {
  const { email, password } = req.body;
  const avatarURL = gravatar.url(email, {
    s: 400,
    r: "pg",
    d: "mm",
  });
  const user = await User.findOne({ email });
  if (user) {
    throw HttpError(409, "Email already used");
  }

  const hashPassword = await bcrypt.hash(password, 10);
  const verificationToken = nanoid();

  const newUser = await User.create({
    ...req.body,
    password: hashPassword,
    avatarURL,
    verificationToken,
  });

  const verifyEmail = {
    to: email,
    subject: "Verification email",
    html: `<a target="_blank" href="${BASE_URL}/api/users/verify/${verificationToken}">Click verify email</a>`,
  };

  await sendEmail(verifyEmail);

  res.status(201).json({
    username: newUser.username,
    email: newUser.email,
  });
};

const verify = async (req, res, next) => {
  const { verificationToken } = req.params;
  const user = await User.findOne({ verificationToken });

  if (!user) {
    throw HttpError(400, "Email invalid or already verified");
  }
  await User.findByIdAndUpdate(user._id, {
    verify: true,
    verificationToken: null,
  });
  res.json({
    message: "Verification successful",
  });
};

const resendVerify = async (req, res, next) => {
  const { email } = req.body;
  const user = await User.findOne({ email });
  if (!user) {
    throw HttpError(400, "Email invalid");
  }
  if (user.verify) {
    throw HttpError(400, "Email already verified");
  }
  const verifyEmail = {
    to: email,
    subject: "Verification email",
    html: `<a target="_blank" href="${BASE_URL}/api/users/verify/${user.verificationToken}">Click verify email</a>`,
  };

  await sendEmail(verifyEmail);

  res.json({
    message: "Email send successfully",
  });
};

const signin = async (req, res) => {
  const { email, password } = req.body;
  const user = await User.findOne({ email });
  if (!user) {
    throw HttpError(401, "Email or password invalid");
  }

  if (!user.verify) {
    throw HttpError(401, "Email not verify");
  }

  const passwordCompare = await bcrypt.compare(password, user.password);
  if (!passwordCompare) {
    throw HttpError(401, "Email or password invalid");
  }

  const { _id: id } = user;

  const payload = {
    id,
  };

  const token = jwt.sign(payload, JWT_SECRET, { expiresIn: "23h" });
  await User.findByIdAndUpdate(id, { token });

  res.json({
    username: user.username,
    email: user.email,
    token,
  });
};

const getCurrent = async (req, res) => {
  const { username, email } = req.user;
  res.json({
    username,
    email,
  });
};

const signout = async (req, res) => {
  const { _id } = req.user;
  await User.findByIdAndUpdate(_id, { token: "" });

  res.json({
    message: "Signout success",
  });
};

const updateUserSubscription = async (req, res) => {
  const { _id } = req.user;
  const result = await User.findByIdAndUpdate(_id, req.body);
  if (!result) {
    throw HttpError(404, `User with id= ${_id} not found`);
  }
  res.json(result);
};

const updateAvatar = async (req, res) => {
  const { _id, username } = req.user;
  const { path: oldPath, filename } = req.file;
  const newFilename = `${username
    .split(" ")
    .join("_")
    .toLowerCase()}_${_id}.${filename.split(".").pop()}`;
  const newPath = path.join(avatarsPath, newFilename);
  const tempPath = path.join("temp", filename);

  try {
    const image = await Jimp.read(oldPath);
    await image
      .autocrop()
      .resize(250, 250, Jimp.RESIZE_BEZIER)
      .circle()
      .write(newPath);
  } catch (err) {
    throw HttpError(500, "Error processing image");
  }
  const newAvatarURL = path.join("avatars", newFilename);
  const result = await User.findByIdAndUpdate(_id, {
    avatarURL: newAvatarURL,
  });
  if (!result) {
    throw HttpError(404, `User with id= ${_id} not found`);
  }
  await fs.unlink(tempPath);

  res.json(result);
};

export default {
  signup: ctrlWrapper(signup),
  verify: ctrlWrapper(verify),
  resendVerify: ctrlWrapper(resendVerify),
  signin: ctrlWrapper(signin),
  getCurrent: ctrlWrapper(getCurrent),
  signout: ctrlWrapper(signout),
  updateUserSubscription: ctrlWrapper(updateUserSubscription),
  updateAvatar: ctrlWrapper(updateAvatar),
};
