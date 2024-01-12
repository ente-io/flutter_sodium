import 'package:flutter/material.dart';
import 'package:flutter_sodium_example/sample_widget.dart';
import 'package:url_launcher/url_launcher_string.dart';
import 'toc.dart';

class TopicPage extends StatelessWidget {
  final Topic topic;

  const TopicPage(this.topic, {Key? key}) : super(key: key);

  @override
  Widget build(BuildContext context) {
    return Scaffold(
        appBar: AppBar(
          title: Text(topic.title),
        ),
        body: SafeArea(
            child: SingleChildScrollView(
                child: Container(
                    padding: const EdgeInsets.all(15.0),
                    child: Column(
                      crossAxisAlignment: CrossAxisAlignment.start,
                      children: <Widget>[
                        // description
                        if (topic.description != null)
                          Padding(
                              padding: const EdgeInsets.only(bottom: 16.0),
                              child: Text(topic.description!)),
                        // more info button
                        if (topic.url != null)
                          Padding(
                            padding: const EdgeInsets.only(bottom: 16.0),
                            child: InkWell(
                                child: const Text(
                                  'More information',
                                  style: TextStyle(color: Colors.blue),
                                ),
                                onTap: () => launchUrlString(topic.url!)),
                          ),
                        // 0..n samples
                        if (topic.samples != null)
                          for (var sample in topic.samples!)
                            Padding(
                                padding: const EdgeInsets.only(bottom: 16.0),
                                child: SampleWidget(sample))
                      ],
                    )))));
  }
}
