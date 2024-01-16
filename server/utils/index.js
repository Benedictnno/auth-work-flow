const { createJWT, isTokenValid, attachCookiesToResponse } = require("./jwt");
const createTokenUser = require("./createTokenUser");
const checkPermissions = require("./checkPermissions");
const sendVerification = require("./sendVerification");
const sendResetPassword = require("./sendResetPassword");
const createHash = require("./hashString");

module.exports = {
  createJWT,
  isTokenValid,
  attachCookiesToResponse,
  createTokenUser,
  checkPermissions,
  sendResetPassword,
  sendVerification,
  createHash,
};
