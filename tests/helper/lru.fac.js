'use strict'

module.exports = () => {
  const cache = {}

  return {
    get: (key) => cache[key],
    set: (key, value) => { cache[key] = value },
    remove: (key) => { delete cache[key] },
    peek: (key) => cache[key]
  }
}
