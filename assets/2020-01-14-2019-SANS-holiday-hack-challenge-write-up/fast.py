#!/usr/bin/python3
# Image Recognition Using Tensorflow Exmaple.
# Code based on example at:
# https://raw.githubusercontent.com/tensorflow/tensorflow/master/tensorflow/examples/label_image/label_image.py
import os
os.environ['TF_CPP_MIN_LOG_LEVEL'] = '3'
import tensorflow as tf
tf.logging.set_verbosity(tf.logging.ERROR)
import numpy as np
import threading
import queue
import time
import sys
import requests
import base64

# sudo apt install python3-pip
# sudo python3 -m pip install --upgrade pip
# sudo python3 -m pip install --upgrade setuptools
# sudo python3 -m pip install --upgrade tensorflow==1.15

def load_labels(label_file):
    label = []
    proto_as_ascii_lines = tf.gfile.GFile(label_file).readlines()
    for l in proto_as_ascii_lines:
        label.append(l.rstrip())
    return label

def predict_image(q, sess, graph, image_bytes, img_uuid, labels, input_operation, output_operation):
    image = read_tensor_from_image_bytes(image_bytes)
    results = sess.run(output_operation.outputs[0], {
        input_operation.outputs[0]: image
    })
    results = np.squeeze(results)
    prediction = results.argsort()[-5:][::-1][0]
    q.put( {'img_uuid':img_uuid, 'prediction':labels[prediction].title(), 'percent':results[prediction]} )

def load_graph(model_file):
    graph = tf.Graph()
    graph_def = tf.GraphDef()
    with open(model_file, "rb") as f:
        graph_def.ParseFromString(f.read())
    with graph.as_default():
        tf.import_graph_def(graph_def)
    return graph

def read_tensor_from_image_bytes(imagebytes, input_height=299, input_width=299, input_mean=0, input_std=255):
    image_reader = tf.image.decode_png( imagebytes, channels=3, name="png_reader")
    float_caster = tf.cast(image_reader, tf.float32)
    dims_expander = tf.expand_dims(float_caster, 0)
    resized = tf.image.resize_bilinear(dims_expander, [input_height, input_width])
    normalized = tf.divide(tf.subtract(resized, [input_mean]), [input_std])
    sess = tf.compat.v1.Session()
    result = sess.run(normalized)
    return result

def main():
    # Loading the Trained Machine Learning Model created from running retrain.py on the training_images directory
    graph = load_graph('/tmp/retrain_tmp/output_graph.pb')
    labels = load_labels("/tmp/retrain_tmp/output_labels.txt")

    # Load up our session
    input_operation = graph.get_operation_by_name("import/Placeholder")
    output_operation = graph.get_operation_by_name("import/final_result")
    sess = tf.compat.v1.Session(graph=graph)

    print("Warmup...")
    image_bytes = open("warmup.png",'rb').read() # Just pick one of the samples previously downloaded, and use it as a "warmup" picture
    predict_image(queue.Queue(), sess, graph, image_bytes, "warmup", labels, input_operation, output_operation)
    print("Warmup done!")

    # Can use queues and threading to spead up the processing
    q = queue.Queue()

    s = requests.Session()

    print('Sending a new captcha request')
    challenge_request_time = time.time()
    challenge = s.post("https://fridosleigh.com/api/capteha/request").json()
    challenge_response_time = time.time()
    print('Challenge received in %.2fs' % (challenge_response_time - challenge_request_time))

    if challenge_response_time - challenge_request_time > 4:
        print("This was too slow ... let's try again")
        print("---------------------------------------------------------------------------")
        return main()

    select_types = [select_type.replace("and ", "").strip() for select_type in challenge["select_type"].split(",")]

    #Going to interate over each of our images.
    for image in challenge["images"]:
        print('%.2f Processing Image %s' % (time.time() - challenge_response_time, image["uuid"]))
        # We don't want to process too many images at once. 10 threads max
        while len(threading.enumerate()) > 10:
            time.sleep(0.01)

        #predict_image function is expecting png image bytes so we read image as 'rb' to get a bytes object
        image_bytes = base64.b64decode(image["base64"])
        threading.Thread(target=predict_image, args=(q, sess, graph, image_bytes, image["uuid"], labels, input_operation, output_operation)).start()
        #predict_image(q, sess, graph, image_bytes, image["uuid"], labels, input_operation, output_operation)

    print('Waiting For Threads to Finish...')
    while q.qsize() < len(challenge["images"]):
        time.sleep(0.001)

    #getting a list of all threads returned results
    prediction_results = [q.get() for x in range(q.qsize())]

    #do something with our results... Like print them to the screen.
    matching_images = []
    for prediction in prediction_results:
        print('TensorFlow Predicted {img_uuid} is a {prediction} with {percent:.2%} Accuracy'.format(**prediction))
        if prediction['prediction'] in select_types:
            matching_images += [prediction["img_uuid"]]

    print("%.2f Submitting response" % (time.time() - challenge_response_time))
    data = {"answer": ",".join(matching_images)}
    response = s.post("https://fridosleigh.com/api/capteha/submit", data=data)
    print("%.2f Result:" % (time.time() - challenge_response_time))
    print(response.text)
    print(s.cookies)

if __name__ == "__main__":
    main()
