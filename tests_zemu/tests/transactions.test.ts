/** ******************************************************************************
 *  (c) 2018 - 2023 Zondax AG
 *
 *  Licensed under the Apache License, Version 2.0 (the "License");
 *  you may not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 ******************************************************************************* */

import Zemu from '@zondax/zemu'
import { NamadaApp, Signature } from '@zondax/ledger-namada'
import { models, hdpath, defaultOptions, tx_empty_memo, tx_empty_field, tx_nanos_crash } from './common'
import { hashSignatureSec } from './utils'
import TEST_DATA from './test_data.json'

// @ts-ignore
import ed25519 from 'ed25519-supercop'

jest.setTimeout(120000)

describe.each(models)('Transactions', function (m) {
  test.concurrent.each(TEST_DATA)('Sign transaction', async function (data) {
    const sim = new Zemu(m.path)
    try {
      await sim.start({ ...defaultOptions, model: m.name })
      const app = new NamadaApp(sim.getTransport())

      const resp_addr = await app.getAddressAndPubKey(hdpath)
      // console.log(resp_addr)

      const respRequest = app.sign(hdpath, Buffer.from(data.blob, 'hex'))
      await sim.waitUntilScreenIsNot(sim.getMainMenuSnapshot(), 20000)
      await sim.compareSnapshotsAndApprove('.', `${m.prefix.toLowerCase()}-sign-${data.name}`)

      const resp = await respRequest
      // console.log(resp, m.name, data.name)

      expect(resp.returnCode).toEqual(0x9000)
      expect(resp.errorMessage).toEqual('No errors')
      expect(resp).toHaveProperty('signature')

      const signature = resp.signature ?? new Signature()
      expect(signature.rawPubkey).toEqual(resp_addr.rawPubkey)
      console.log(signature)
      // Verify raw signature
      const unsignedRawSigHash = hashSignatureSec([], signature.raw_salt, data.sectionIndices, data.sectionHashes, signature.raw_indices, null, null)
      const rawSig = ed25519.verify(signature.raw_signature.subarray(1), unsignedRawSigHash, signature.rawPubkey.subarray(1))

      // Verify wrapper signature
      const prefix = new Uint8Array([0x03])
      const rawHash: Buffer = hashSignatureSec(
        [signature.rawPubkey],
        signature.raw_salt,
        data.sectionIndices,
        data.sectionHashes,
        signature.raw_indices,
        signature.raw_signature,
        prefix,
      )
      const tmpIndices = [ ...data.sectionIndices ]
      const tmpHashes = [ ...data.sectionHashes ]

      tmpIndices.push(data.sectionHashes.length - 1)
      tmpHashes.push(rawHash.toString('hex'))

      const unsignedWrapperSigHash = hashSignatureSec([], signature.wrapper_salt, tmpIndices, tmpHashes, signature.wrapper_indices, null, null)
      const wrapperSig = ed25519.verify(signature.wrapper_signature.subarray(1), unsignedWrapperSigHash, resp_addr.rawPubkey.subarray(1))

      expect(wrapperSig && rawSig).toEqual(true)
    } finally {
      await sim.close()
    }
  })

  test.concurrent('Sign transaction with empty memo', async function () {
    const sim = new Zemu(m.path)
    try {
      await sim.start({ ...defaultOptions, model: m.name })
      const app = new NamadaApp(sim.getTransport())

      const resp_addr = await app.getAddressAndPubKey(hdpath)

      const respRequest = app.sign(hdpath, Buffer.from(tx_empty_memo, 'hex'))
      await sim.waitUntilScreenIsNot(sim.getMainMenuSnapshot(), 20000)
      await sim.compareSnapshotsAndApprove('.', `${m.prefix.toLowerCase()}-sign-empty-memo`)

      const resp = await respRequest

      expect(resp.returnCode).toEqual(0x9000)
      expect(resp.errorMessage).toEqual('No errors')
      expect(resp).toHaveProperty('signature')
    } finally {
      await sim.close()
    }
  })

  test.concurrent('Sign transaction with empty field Issue 106', async function () {
    const sim = new Zemu(m.path)
    try {
      await sim.start({ ...defaultOptions, model: m.name })
      const app = new NamadaApp(sim.getTransport())

      const resp_addr = await app.getAddressAndPubKey(hdpath)

      const respRequest = app.sign(hdpath, Buffer.from(tx_empty_field, 'hex'))
      await sim.waitUntilScreenIsNot(sim.getMainMenuSnapshot(), 20000)
      await sim.compareSnapshotsAndApprove('.', `${m.prefix.toLowerCase()}-sign-empty-field`)

      const resp = await respRequest

      expect(resp.returnCode).toEqual(0x9000)
      expect(resp.errorMessage).toEqual('No errors')
      expect(resp).toHaveProperty('signature')
    } finally {
      await sim.close()
    }
  })

  test.concurrent('Verify nanoS crash Issue 110', async function () {
    const sim = new Zemu(m.path)
    try {
      await sim.start({ ...defaultOptions, model: m.name })
      const app = new NamadaApp(sim.getTransport())

      // Activate expert mode
      await sim.toggleExpertMode();

      const resp_addr = await app.getAddressAndPubKey(hdpath)

      const respRequest = app.sign(hdpath, Buffer.from(tx_nanos_crash, 'hex'))
      await sim.waitUntilScreenIsNot(sim.getMainMenuSnapshot(), 20000)
      await sim.compareSnapshotsAndApprove('.', `${m.prefix.toLowerCase()}-sign-crash`)

      const resp = await respRequest

      expect(resp.returnCode).toEqual(0x9000)
      expect(resp.errorMessage).toEqual('No errors')
      expect(resp).toHaveProperty('signature')
    } finally {
      await sim.close()
    }
  })
})
