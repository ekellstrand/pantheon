/*
 * Copyright 2019 ConsenSys AG.
 *
 * Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with
 * the License. You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software distributed under the License is distributed on
 * an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the License for the
 * specific language governing permissions and limitations under the License.
 */
package tech.pegasys.pantheon.tests.web3j.privacy;

import static java.nio.charset.StandardCharsets.UTF_8;
import static tech.pegasys.pantheon.tests.acceptance.dsl.WaitUtils.waitFor;

import tech.pegasys.orion.testutil.OrionTestHarness;
import tech.pegasys.pantheon.crypto.SECP256K1;
import tech.pegasys.pantheon.enclave.Enclave;
import tech.pegasys.pantheon.enclave.types.SendRequest;
import tech.pegasys.pantheon.tests.acceptance.dsl.node.PantheonNode;
import tech.pegasys.pantheon.util.bytes.BytesValue;

import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class PrivacyNode {
  private static final Logger LOG = LogManager.getLogger();

  public PantheonNode pantheon;
  public OrionTestHarness orion;
  public SECP256K1.KeyPair pantheonNodeKeypair;
  public String orionPubKey;
  private Map<String, Long> noncesByPrivacyGroup = new HashMap<>();

  public PrivacyNode(
      final PantheonNode pantheon,
      final OrionTestHarness orion,
      final SECP256K1.KeyPair pantheonNodeKeypair,
      final String orionPubKey) {
    this.pantheon = pantheon;
    this.orion = orion;
    this.pantheonNodeKeypair = pantheonNodeKeypair;
    this.orionPubKey = orionPubKey;
  }

  public BytesValue getOrionPubKeyBytes() {
    return BytesValue.wrap(orionPubKey.getBytes(UTF_8));
  }

  public void testOrionConnection(final PrivacyNode otherNode) {
    LOG.info(
        String.format(
            "Testing Orion connectivity between %s (%s) and %s (%s)",
            pantheon.getName(),
            orion.nodeUrl(),
            otherNode.pantheon.getName(),
            otherNode.orion.nodeUrl()));
    Enclave orionEnclave = new Enclave(orion.clientUrl());
    SendRequest sendRequest1 =
        new SendRequest(
            "SGVsbG8sIFdvcmxkIQ==", orion.getPublicKeys().get(0), otherNode.orion.getPublicKeys());
    waitFor(() -> orionEnclave.send(sendRequest1));
  }

  /*
    private long getNonce(final PantheonNode node, final String privacyGroupId) {
      return node.execute(
              privateTransactions.getTransactionCount(node.getAddress().toString(), privacyGroupId))
          .longValue();
    }
  */

  // TODO: Convert this to check the blockchain instead of tracking here.
  public long getNonce(final int[] privacyGroupNodes) {
    List<Integer> list = Arrays.stream(privacyGroupNodes).boxed().collect(Collectors.toList());
    String key = list.stream().map(Object::toString).collect(Collectors.joining(","));
    Long nonce = noncesByPrivacyGroup.getOrDefault(key, -1L);
    noncesByPrivacyGroup.put(key, ++nonce);
    return nonce;
  }
}
