/** @type {import('ts-jest').JestConfigWithTsJest} **/
module.exports = {
  testEnvironment: "node",
  setupFilesAfterEnv: ['./jest-setup.js'],
  transform: {
    "^.+\.tsx?$": ["ts-jest",{}],
  },
};