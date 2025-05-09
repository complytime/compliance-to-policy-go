/*
Copyright 2023 IBM Corporation

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package ocmk8sclients

import (
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	"k8s.io/client-go/dynamic"

	"github.com/oscal-compass/compliance-to-policy-go/v2/pkg"
	typespolicy "github.com/oscal-compass/compliance-to-policy-go/v2/pkg/types/policy"
)

var _ = Describe("Test CRUD of Policy", func() {

	typedObj := typespolicy.Policy{}
	err := pkg.LoadYamlFileToK8sTypedObject(testdataDir+"/policy.sample.yaml", &typedObj)
	Expect(err).NotTo(HaveOccurred())

	var clientInterface dynamic.NamespaceableResourceInterface
	var client policyClient

	BeforeEach(func() {
		clientInterface = ocmK8ResourceInterfaceSet.Policy
		client = NewPolicyClient(clientInterface)
	})

	Context("When creating Policy", func() {
		It("should create the object", func() {
			_typedObj, err := client.Create(sampleNamespace, typedObj)
			Expect(err).NotTo(HaveOccurred())
			Expect(_typedObj).NotTo(BeNil())
		})
		It("should list the created object", func() {
			typedList, err := client.List(sampleNamespace)
			Expect(err).NotTo(HaveOccurred())
			Expect(len(typedList)).To(Equal(1))
		})
		It("should get the created object", func() {
			fetchedTypedObj, err := client.Get(sampleNamespace, typedObj.Name)
			Expect(err).NotTo(HaveOccurred())
			Expect(fetchedTypedObj).NotTo(BeNil())
			Expect(fetchedTypedObj.Name).To(Equal(typedObj.Name))
		})
	})

	Context("When deleting Policy", func() {
		It("should delete the object", func() {
			err = client.Delete(sampleNamespace, typedObj.Name)
			Expect(err).NotTo(HaveOccurred())
		})
		It("should list no object", func() {
			typedList, err := client.List(sampleNamespace)
			Expect(err).NotTo(HaveOccurred())
			Expect(len(typedList)).To(Equal(0))
		})
	})
})
